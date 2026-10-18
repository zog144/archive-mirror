import json
import os
import time
from pathlib import Path
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views.decorators.http import require_GET
from django.utils.html import format_html, format_html_join
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .config import configuration, collection
from .lease import lease
from .models import Archive, CollectionStatus
from .store import open_object

def keys(config):
    import base64
    value=json.loads(Path(config['keyring']).read_text())
    if value['version']!=1:raise ValueError('Unsupported keyring')
    return {name:Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded,validate=True)) for name,encoded in value['keys'].items()}

def authorize(request,operation,target):
    lease();config=configuration()
    header=request.headers.get('Authorization','')
    if not header.startswith('Bearer '):raise PermissionError('Token required')
    from zog.host_identify.archive import verify
    verify(header[7:],keys(config),config['issuer'],config['audience'],operation,target)
    collection(target)

def boundary(view):
    def wrapped(request,*args,**kwargs):
        try:response=view(request,*args,**kwargs)
        except PermissionError:response=JsonResponse({'detail':'Archive authorization denied'},status=403)
        except Archive.DoesNotExist:response=JsonResponse({'detail':'Archive not found'},status=404)
        except (ValueError,OSError,KeyError,TypeError):response=JsonResponse({'detail':'Archive service unavailable'},status=503)
        response['Cache-Control']='no-store'
        response['X-Content-Type-Options']='nosniff'
        return response
    return wrapped

def public_provenance(value):
    """Catalogues never echo arbitrary import metadata, source URLs or credentials."""
    import re
    if not isinstance(value, dict): return {}
    result = {}
    for key in ('commit', 'generation'):
        text = value.get(key)
        if isinstance(text, str) and re.fullmatch(r'[0-9a-f]{7,64}', text): result[key] = text
    if type(value.get('release_approved')) is bool: result['release_approved'] = value['release_approved']
    for key, allowed in [('import', 'local'), ('export_recipe', 'tracked-tree-v1'), ('attributes', 'ignored')]:
        if value.get(key) == allowed: result[key] = allowed
    if value.get('reviewed_source') is True:
        result['reviewed_source'] = True
        from urllib.parse import urlsplit
        url=value.get('canonical_url')
        if isinstance(url,str):
            parts=urlsplit(url)
            if parts.scheme=='https' and parts.hostname and not parts.username and not parts.password and not parts.query and not parts.fragment:
                result['origin_url']=url
    return result

def reviewed_provenance(archive):
    rows=(archive.reviewed_sources.select_related('pin_set').order_by('pin_set_id','package','source','canonical_url')[:25])
    return [{'pin_set':x.pin_set_id,'complete':x.pin_set.complete,'active':x.pin_set.active,
             'package':x.package,'source':x.source,'canonical_url':x.canonical_url} for x in rows]

def item(archive):
    value={'sha256':archive.digest,'bytes':archive.size,'kind':archive.kind,'collection':archive.collection,
            'created':archive.created,'provenance':public_provenance(archive.provenance),
            'download':'/collections/'+archive.collection+'/archives/'+archive.digest+'.tar.xz',
            'object_download':'/collections/'+archive.collection+'/objects/'+archive.digest}
    reviewed=reviewed_provenance(archive)
    if reviewed:value['reviewed_sources']=reviewed
    return value

@require_GET
@boundary
def catalogue(request,target):
    authorize(request,'list',target)
    try:
        page=int(request.GET.get('page','1'));version=int(request.GET.get('version','1'))
    except ValueError:return JsonResponse({'detail':'Invalid page'},status=400)
    if version not in (1,2) or not 1<=page<=100000:return JsonResponse({'detail':'Invalid page'},status=400)
    rows=list(Archive.objects.filter(collection=target).order_by('id')[(page-1)*100:page*100+1])
    entries=[item(x) for x in rows[:100]]
    if version==2:
        from .notices import summary
        for entry,archive in zip(entries,rows):entry['licenses']=summary(archive)
    return JsonResponse({'collection_status':list(CollectionStatus.objects.order_by('source').values()) if target=='sources' else [],'version':version,'archives':entries,'next_page':page+1 if len(rows)>100 else None})

def _download(request,target,digest,filename,content_type):
    authorize(request,'download',target)
    archive=Archive.objects.get(collection=target,digest=digest)
    stream=open_object(digest)
    if os.fstat(stream.fileno()).st_size!=archive.size:
        stream.close();raise ValueError('Object size mismatch')
    response=FileResponse(stream,as_attachment=True,filename=filename,content_type=content_type)
    response['Content-Length']=str(archive.size);response['ETag']='"sha256:'+digest+'"'
    response['X-Archive-SHA256']=digest
    return response

@require_GET
@boundary
def download(request,target,digest):
    return _download(request,target,digest,digest+'.tar.xz','application/x-xz')

@require_GET
@boundary
def object_download(request,target,digest):
    return _download(request,target,digest,digest,'application/octet-stream')

@require_GET
@boundary
def ready(request):
    intent=lease();config=configuration();keys(config);root=Path(config['root'])
    health=json.loads((root/'scheduler.json').read_text())
    desired=intent['desired']
    if health['host_id']!=intent['host_id'] or health['revision']!=desired['revision'] or not 0<=time.time()-health['time']<=45:
        raise ValueError('Scheduler stale')
    Archive.objects.exists()
    fd=os.open(root/'objects',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.close(fd)
    return JsonResponse({'version':1,'host_id':intent['host_id'],'role_revision':desired['revision'],'serving':True,'scheduler_running':True})

@require_GET
@boundary
def administrator_catalogue(request):
    if not getattr(getattr(request,'user',None),'is_authenticated',False):return HttpResponse('Login required',status=401)
    if not request.user.is_superuser:return HttpResponse('Administrator required',status=403)
    lease()
    rows=Archive.objects.order_by('-created')[:100]
    body=format_html_join('', '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>',((x.collection,x.kind,x.digest,x.size) for x in rows))
    return HttpResponse(format_html('<!doctype html><html><title>Archive catalogue</title><h1>Archive catalogue</h1><p>Latest 100 records. Machine downloads require an archive token.</p><table><tr><th>Collection</th><th>Type</th><th>SHA-256</th><th>Bytes</th></tr>{}</table></html>',body))

@boundary
def notice(request, target, digest):
    if request.method != 'GET':
        return HttpResponse(status=405)
    authorize(request, 'download', target)
    from . import notices, notice_contract
    archive = Archive.objects.get(collection=target, digest=digest)
    try:
        value = notices.read(archive)
    except FileNotFoundError:
        return JsonResponse({'detail': 'License information unavailable'}, status=404)
    if set(request.GET) - {'offset', 'limit', 'format'} or any(len(request.GET.getlist(k)) != 1 for k in request.GET):
        return HttpResponse(status=400)
    if request.GET.get('format') == 'text':
        result = HttpResponse(notice_contract.document(value), content_type='text/plain; charset=utf-8')
        result['Content-Disposition'] = 'attachment; filename="notices-' + digest + '.txt"'
        result['Content-Security-Policy'] = "default-src 'none'; sandbox"
        return result
    if request.GET.get('format', 'metadata') != 'metadata':
        return HttpResponse(status=400)
    offset, limit = int(request.GET.get('offset', 0)), int(request.GET.get('limit', 25))
    if not 0 <= offset <= notice_contract.MAX_RECORDS or not 1 <= limit <= 25:
        return HttpResponse(status=400)
    return JsonResponse(dict(schema=1, summary=notice_contract.summary(value), records=value['records'][offset:offset+limit],
        next_offset=offset+limit if offset+limit < len(value['records']) else None))
