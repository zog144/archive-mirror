import argparse
import json
import os
import sys

def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('migrate');sub.add_parser('refresh');sub.add_parser('prune');sub.add_parser('scheduler')
    cutover=sub.add_parser('cutover-evidence');cutover.add_argument('--root',required=True)
    serving=sub.add_parser('serve');serving.add_argument('--host',default='127.0.0.1');serving.add_argument('--port',type=int,default=8080)
    importing=sub.add_parser('import');importing.add_argument('path');importing.add_argument('--collection',required=True);importing.add_argument('--kind',choices=['source','root-filesystem'],required=True)
    reviewed=sub.add_parser('populate-sources');reviewed.add_argument('manifest')
    release=sub.add_parser('release-source-pin-set');release.add_argument('identity')
    abandon=sub.add_parser('abandon-source-pin-set');abandon.add_argument('identity')
    notice=sub.add_parser('notices');notice.add_argument('collection');notice.add_argument('digest')
    evidence=notice.add_mutually_exclusive_group(required=True)
    evidence.add_argument('--source-record');evidence.add_argument('--sidecar');evidence.add_argument('--rootfs-receipts',action='store_true')
    notice.add_argument('--generation');notice.add_argument('--retained-inputs')
    importing.add_argument('--license-sidecar');importing.add_argument('--source-record')
    importing.add_argument('--rootfs-receipts',action='store_true');importing.add_argument('--generation');importing.add_argument('--retained-inputs')
    for name in ('pin','unpin'):
        p=sub.add_parser(name);p.add_argument('collection');p.add_argument('digest');p.add_argument('name')
    args=parser.parse_args()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE','zog.archive_mirror.settings')
    import django;django.setup()
    from . import store
    try:
        if args.command=='migrate':
            from django.core.management import call_command
            call_command('migrate',interactive=False)
        elif args.command=='import':
            record=store.publish(args.path,args.collection,args.kind,{'import':'local','release_approved':False})
            if args.license_sidecar or args.rootfs_receipts or args.source_record:
                attach_notices(record, args.license_sidecar, args.rootfs_receipts, args.generation, args.retained_inputs, args.source_record)
            print(json.dumps({'sha256':record.digest,'bytes':record.size}))
        elif args.command=='populate-sources':
            from .source_inputs import populate
            pin_set,archives=populate(args.manifest)
            print(json.dumps({'pin_set':pin_set.identity,'manifest_sha256':pin_set.manifest_sha256,
                'active':pin_set.active,'sources':len(archives),'digests':sorted({x.digest for x in archives})}))
        elif args.command=='release-source-pin-set':
            from .source_inputs import deactivate
            pin_set=deactivate(args.identity)
            print(json.dumps({'pin_set':pin_set.identity,'active':pin_set.active,'complete':pin_set.complete}))
        elif args.command=='abandon-source-pin-set':
            from .source_inputs import abandon
            identity=abandon(args.identity)
            print(json.dumps({'pin_set':identity,'abandoned':True}))
        elif args.command=='notices':
            from .models import Archive
            record=Archive.objects.get(collection=args.collection,digest=args.digest)
            print(json.dumps(attach_notices(record,args.sidecar,args.rootfs_receipts,args.generation,args.retained_inputs,args.source_record)))
        elif args.command in ('pin','unpin'):store.pin(args.collection,args.digest,args.name,args.command=='unpin')
        elif args.command=='prune':store.prune()
        elif args.command=='refresh':
            from .collector import collect
            from .config import configuration
            from .lease import lease
            from .models import CollectionStatus
            from django.utils import timezone
            failed=False
            for definition in configuration().get('sources',[]):
                lease()
                status,_=CollectionStatus.objects.update_or_create(source=definition['name'],defaults={'last_attempt':timezone.now()})
                try:
                    collect(definition,require_lease=True)
                    status.last_success=timezone.now();status.error='';status.save()
                except Exception as error:
                    status.error=type(error).__name__;status.save()
                    print('Collection failed: '+type(error).__name__,file=sys.stderr);failed=True
            lease();store.prune()
            if failed:raise RuntimeError('Some sources failed')
        elif args.command=='scheduler':
            from .runtime import scheduler
            scheduler()
        elif args.command=='cutover-evidence':
            from .cutover_evidence import collect
            print(json.dumps(collect(args.root),sort_keys=True))
        elif args.command=='serve':
            from .runtime import server
            server(args.host,args.port)
    except Exception as error:
        print('archive-mirror failed: '+type(error).__name__,file=sys.stderr);return 1
    return 0

def attach_notices(record, sidecar, rootfs, generation, retained_inputs, source_record=None):
    from . import notices, notice_contract
    if sum(bool(x) for x in (sidecar, rootfs, source_record)) != 1:
        raise ValueError('Choose one evidence source')
    if source_record:
        from .source_notices import build
        value=build(record,source_record)
    elif rootfs:
        from .receipt_notices import build
        value=build(record,generation,retained_inputs)
    else:
        with open(sidecar,'rb') as stream:
            value=notice_contract.decode(stream.read(notice_contract.MAX_BUNDLE+1))
    return notices.publish(record,value)
