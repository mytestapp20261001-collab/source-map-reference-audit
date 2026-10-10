import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def make(self,**kw):
        doc={'version':3,'sources':['src.js'],'names':[],'mappings':''};doc.update(kw)
        p=self.root/'bundle.map';p.write_text(json.dumps(doc));return p
    def test_local_and_cli(self):
        (self.root/'src.js').write_text('const x=1;\n');p=self.make();r=tool.audit(p,root=self.root);self.assertEqual(r['status'],'pass');self.assertFalse(r['summary']['mappings_validated']);self.assertEqual(self.call(p,'--root',self.root)[0],0)
    def test_missing_and_cli(self):
        p=self.make();self.assertIn('missing_local_source',self.codes(tool.audit(p,root=self.root)));self.assertEqual(self.call(p,'--root',self.root)[0],1)
    def test_embedded_coverage_and_compare(self):
        p=self.make(sourcesContent=['synthetic']);self.assertEqual(tool.audit(p,root=self.root)['status'],'pass');(self.root/'src.js').write_text('different')
        self.assertIn('embedded_content_mismatch',self.codes(tool.audit(p,root=self.root,check_embedded_files=True)))
        p=self.make(sourcesContent=[]);self.assertIn('sources_content_length_mismatch',self.codes(tool.audit(p,root=self.root)))
    def test_nonlocal_scope_and_encoded_traversal(self):
        p=self.make(sources=['https://example.invalid/secret','../private','%2e%2e/private','a%2fb'])
        r=tool.audit(p,root=self.root);self.assertTrue({'nonlocal_reference','outside_scope','encoded_separator_reference'}<=self.codes(r));self.assertNotIn('secret',json.dumps(r))
    def test_source_root_and_parent_reference(self):
        (self.root/'src').mkdir();(self.root/'src'/'x.js').touch();p=self.make(sourceRoot='src',sources=['x.js']);self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')
        maps=self.root/'maps';maps.mkdir();p=maps/'a.map';p.write_text(json.dumps({'version':3,'sources':['../src/x.js'],'mappings':''}));self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')
    def test_symlink_never_read(self):
        (self.root/'src.js').symlink_to('/definitely-outside');p=self.make();self.assertIn('symlink_reference',self.codes(tool.audit(p,root=self.root)))
        (self.root/'d').symlink_to('/definitely-outside');p=self.make(sources=['d/../src.js']);self.assertIn('symlink_reference',self.codes(tool.audit(p,root=self.root)))
    def test_schema_and_duplicates(self):
        p=self.make(version=True);self.assertEqual(tool.audit(p,root=self.root)['status'],'error');p=self.make(sections=[]);self.assertEqual(tool.audit(p,root=self.root)['status'],'error')
        p.write_text('{"version":3,"version":3}');self.assertEqual(tool.audit(p,root=self.root)['status'],'error')
        p=self.make(sources=[None],sourcesContent=['embedded']);self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')
    def test_limits_and_permission(self):
        p=self.make(sources=['a','b']);self.assertEqual(tool.audit(p,root=self.root,max_sources=1)['status'],'error');self.assertEqual(tool.audit(p,root=self.root,max_bytes=1)['status'],'error')
        with mock.patch.object(tool,'read_file',side_effect=PermissionError):self.assertEqual(tool.audit(p,root=self.root)['status'],'error')
    def test_content_budget_and_query(self):
        p=self.make(sourcesContent=['hello']);(self.root/'src.js').write_text('hello');self.assertEqual(tool.audit(p,root=self.root,check_embedded_files=True,max_total_source_bytes=1)['status'],'error')
        p=self.make(sources=['src.js?x']);self.assertIn('query_or_fragment_reference',self.codes(tool.audit(p,root=self.root)))

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()

    def test_empty_query_fragment_delimiters_are_findings(self):
        for reference in ('a.js?','a.js#','a.js?#'):
            with self.subTest(reference=reference):
                p=self.make(sources=[reference],sourcesContent=['synthetic'])
                self.assertIn('query_or_fragment_reference',self.codes(tool.audit(p,root=self.root)))
                self.assertEqual(self.call(p,'--root',self.root)[0],1)
        for prefix in ('src?','src#'):
            p=self.make(sourceRoot=prefix,sources=['a.js'],sourcesContent=['synthetic'])
            self.assertIn('query_or_fragment_reference',self.codes(tool.audit(p,root=self.root)))
    def test_percent_encoded_question_and_hash_are_file_names(self):
        for name in ('a.js?','a.js#'):(self.root/name).write_text('synthetic')
        p=self.make(sources=['a.js%3F','a.js%23'])
        self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')
        self.assertEqual(self.call(p,'--root',self.root)[0],0)


    def test_source_root_cannot_mask_nonlocal_sources(self):
        for source in ('/absolute.js','//server/share.js','https://example.invalid/a.js','C:/drive.js','%2Fabsolute.js','C%3A/drive.js'):
            with self.subTest(source=source):
                p=self.make(sourceRoot='src',sources=[source],sourcesContent=['embedded'])
                expected='encoded_separator_reference' if source.startswith('%2F') else 'nonlocal_reference'
                self.assertIn(expected,self.codes(tool.audit(p,root=self.root)))
                self.assertEqual(self.call(p,'--root',self.root)[0],1)

    def test_source_root_is_validated_independently(self):
        for prefix in ('https://example.invalid','/absolute','//server/share','C:/drive'):
            with self.subTest(prefix=prefix):
                p=self.make(sourceRoot=prefix,sources=[],sourcesContent=[])
                self.assertIn('nonlocal_reference',self.codes(tool.audit(p,root=self.root)))
                self.assertEqual(self.call(p,'--root',self.root)[0],1)
        for prefix in ('src?','src#','a%2fb'):
            p=self.make(sourceRoot=prefix,sources=['a.js'],sourcesContent=['embedded'])
            self.assertEqual(tool.audit(p,root=self.root)['status'],'findings')

    def test_relative_source_root_and_parent_remain_valid(self):
        (self.root/'src').mkdir();(self.root/'src'/'a.js').write_text('content')
        p=self.make(sourceRoot='src/',sources=['a.js'],sourcesContent=['content'])
        self.assertEqual(tool.audit(p,root=self.root,check_embedded_files=True)['status'],'pass')
        maps=self.root/'maps';maps.mkdir();p=maps/'bundle.map'
        p.write_text(json.dumps({'version':3,'sourceRoot':'../src','sources':['a.js'],'mappings':''}))
        self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')
        p.write_text(json.dumps({'version':3,'sourceRoot':'.','sources':['../src/a.js'],'mappings':''}))
        self.assertEqual(tool.audit(p,root=self.root)['status'],'pass')

if __name__=="__main__":unittest.main()
