#!/usr/bin/env python3
"""Audit v3 flat source-map reference coverage within a chosen local root."""
import json
import ntpath
import os
import re
import stat
from urllib.parse import unquote, urlsplit
from _support import InputError, Parser, Report, _flags, anchored, cli, guarded, limits, positive, read_fd, read_file
TOOL='source-map-reference-audit'

def pairs(items):
    result={}
    for key,value in items:
        if key in result:raise InputError('duplicate JSON object keys are unsupported')
        result[key]=value
    return result

def local_parts(reference):
    if any(ord(c)<32 for c in reference) or '\\' in reference:return None,'unsupported_reference_syntax'
    if re.search(r'%(?![0-9a-fA-F]{2})',reference):return None,'invalid_percent_encoding'
    u=urlsplit(reference)
    if u.scheme or u.netloc or u.path.startswith('/') or ntpath.splitdrive(u.path)[0]:return None,'nonlocal_reference'
    if '?' in reference or '#' in reference:return None,'query_or_fragment_reference'
    if re.search(r'%(?:2f|5c)',u.path,re.I):return None,'encoded_separator_reference'
    decoded=unquote(u.path,encoding='utf-8',errors='strict')
    if any(ord(c)<32 for c in decoded) or '\\' in decoded:return None,'unsupported_reference_syntax'
    if decoded.startswith('/') or ntpath.splitdrive(decoded)[0]:return None,'nonlocal_reference'
    if not decoded:return None,'empty_reference'
    return decoded.split('/'),None

def lexical_scope(parts):
    depth=0
    for part in parts:
        if part in ('','.'):continue
        if part=='..':
            depth-=1
            if depth<0:return False
        else:depth+=1
    return True

def probe(root_fd,parts,read_content,max_source_bytes):
    stack=[os.dup(root_fd)]
    try:
        for i,part in enumerate(parts):
            if part in ('','.'):continue
            if part=='..':
                if len(stack)==1:return 'outside_scope',None
                os.close(stack.pop());continue
            try:st=os.stat(part,dir_fd=stack[-1],follow_symlinks=False)
            except FileNotFoundError:return 'missing_local_source',None
            if stat.S_ISLNK(st.st_mode):return 'symlink_reference',None
            last=i==len(parts)-1
            if not last:
                if not stat.S_ISDIR(st.st_mode):return 'non_directory_reference_component',None
                child=os.open(part,_flags(True),dir_fd=stack[-1])
                actual=os.fstat(child)
                if (actual.st_dev,actual.st_ino)!=(st.st_dev,st.st_ino):
                    os.close(child);raise InputError('source tree changed during scan')
                stack.append(child)
            elif not stat.S_ISREG(st.st_mode):return 'non_regular_source',None
            elif read_content:
                fd=os.open(part,_flags(),dir_fd=stack[-1])
                try:
                    actual=os.fstat(fd)
                    if (actual.st_dev,actual.st_ino)!=(st.st_dev,st.st_ino):raise InputError('source changed during scan')
                    return None,read_fd(fd,max_source_bytes)
                finally:os.close(fd)
            else:return None,None
        return 'non_regular_source',None
    finally:
        for fd in stack:os.close(fd)

@guarded(TOOL)
def audit(path, *, root,check_embedded_files=False,max_bytes=16777216,max_sources=100000,max_source_bytes=16777216,max_total_source_bytes=134217728,max_findings=1000):
    limits(max_bytes=max_bytes,max_sources=max_sources,max_source_bytes=max_source_bytes,max_total_source_bytes=max_total_source_bytes,max_findings=max_findings)
    root_path=os.path.abspath(root);map_path=os.path.abspath(path)
    if os.path.commonpath([root_path,map_path])!=root_path:raise InputError('map file must be inside the explicitly selected root')
    try:
        doc=json.loads(read_file(path,max_bytes).decode('utf-8','strict'),object_pairs_hook=pairs,
                       parse_constant=lambda value:(_ for _ in ()).throw(InputError('non-finite JSON numbers are unsupported')))
    except (UnicodeDecodeError,json.JSONDecodeError):raise InputError('expected a UTF-8 JSON source map') from None
    if not isinstance(doc,dict) or type(doc.get('version')) is not int or doc['version']!=3:raise InputError('expected source-map version 3')
    if 'sections' in doc:raise InputError('indexed source maps are outside this flat-map audit scope')
    sources=doc.get('sources');contents=doc.get('sourcesContent');source_root=doc.get('sourceRoot')
    if not isinstance(sources,list) or any(x is not None and not isinstance(x,str) for x in sources):raise InputError('sources must be an array of strings or null')
    if len(sources)>max_sources:raise InputError('source-count limit exceeded')
    if contents is not None and (not isinstance(contents,list) or any(x is not None and not isinstance(x,str) for x in contents)):raise InputError('sourcesContent must be an array of strings or null')
    if source_root is not None and not isinstance(source_root,str):raise InputError('sourceRoot must be a string or null')
    if not isinstance(doc.get('mappings'),str):raise InputError('mappings must be a string; VLQ validation is not performed')
    if 'names' in doc and (not isinstance(doc['names'],list) or any(not isinstance(x,str) for x in doc['names'])):raise InputError('names must be an array of strings')
    report=Report(TOOL,max_findings)
    if contents is not None and len(contents)!=len(sources):report.add('sources_content_length_mismatch',sources=len(sources),contents=len(contents))
    base=os.path.relpath(os.path.dirname(map_path),root_path)
    base_parts=[] if base=='.' else base.split(os.sep)
    prefix=(source_root+('' if source_root.endswith('/') else '/')) if source_root else ''
    # Validate each raw URL-path before prefixing; a relative prefix must not
    # disguise a source URL, absolute path, drive path, or other rejected form.
    prefix_code=None
    if source_root:
        _,prefix_code=local_parts(source_root)
        if prefix_code:report.add(prefix_code,field='sourceRoot')
    checked=embedded=total=0;seen={}
    with anchored(root,True) as root_fd:
        for index,source in enumerate(sources):
            content=contents[index] if contents is not None and index<len(contents) else None
            if content is not None:embedded+=1
            if source is None:
                if content is None:report.add('source_without_reference_or_content',source=index)
                continue
            _,code=local_parts(source)
            if code:report.add(code,source=index);continue
            if prefix_code:continue
            parts,code=local_parts(prefix+source)
            if code:report.add(code,source=index);continue
            full=base_parts+parts
            if not lexical_scope(full):report.add('outside_scope',source=index);continue
            normalized=os.path.normpath('/'.join(full))
            if normalized in seen:report.add('duplicate_local_reference',source=index,other_source=seen[normalized])
            else:seen[normalized]=index
            if content is not None and not check_embedded_files:continue
            remaining=max_total_source_bytes-total
            code,data=probe(root_fd,full,content is not None,min(max_source_bytes,remaining))
            checked+=1
            if code:report.add(code,source=index);continue
            if data is not None:
                total+=len(data)
                try:actual=data.decode('utf-8','strict')
                except UnicodeDecodeError:report.add('local_source_not_utf8',source=index);continue
                if actual!=content:report.add('embedded_content_mismatch',source=index)
    return report.finish({'sources':len(sources),'embedded_sources':embedded,'local_references_checked':checked,'local_content_bytes_read':total,'mappings_validated':False})

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument('map');p.add_argument('--root',required=True);p.add_argument('--check-embedded-files',action='store_true')
    for name,default in [('max-bytes',16777216),('max-sources',100000),('max-source-bytes',16777216),('max-total-source-bytes',134217728),('max-findings',1000)]:p.add_argument('--'+name,type=positive,default=default)
    a=vars(p.parse_args());path=a.pop('map');return audit(path,**a)
if __name__=='__main__':raise SystemExit(cli(TOOL,parse_and_audit))
