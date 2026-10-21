"""Entire local approval-to-download demonstration. Never connects to a live host."""
import json,os,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve()
mirror_source=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(mirror_source))
for p in ['station-access/backend']:sys.path.insert(0,str(root/p))
with tempfile.TemporaryDirectory(prefix='host-identify-demo-') as directory:
    os.environ['STATION_ACCESS_STATE_DIRECTORY']=directory
    os.environ['DJANGO_SETTINGS_MODULE']='station_access_project.settings'
    os.environ['HOST_IDENTITY_ORIGIN']='https://registry.example.test'
    os.environ['STATION_ACCESS_ALLOWED_HOSTS']='registry.example.test,testserver'
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from zog.host_identify import signatures
    issuer=Ed25519PrivateKey.generate();key=Ed25519PrivateKey.generate()
    private=Path(directory)/'issuer.pem';private.write_bytes(issuer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
    config=Path(directory)/'issuer.json';config.write_text(json.dumps({'private_key_file':str(private),'key_id':'demo','issuer':'https://registry.example.test','audience':'mirror-demo','mirror':'https://mirror.example.test'}))
    os.environ['HOST_ARCHIVE_CONFIGURATION']=str(config)
    os.environ['ARCHIVE_MIRROR_CONFIGURATION']=str(Path(directory)/'mirror.json')
    import django;django.setup()
    from django.core.management import call_command
    call_command('migrate',verbosity=0)
    from django.test import Client
    from django.contrib.auth import get_user_model
    administrator=Client();administrator.force_login(get_user_model().objects.create_superuser('demo-admin',password=None))
    machine=Client();origin='https://registry.example.test';fingerprint=signatures.fingerprint(key.public_key())
    def signed(path,payload,subject):
        m=signatures.sign(origin+path,json.dumps(payload).encode(),key,subject)
        headers={'HTTP_'+k.upper().replace('-','_'):v for k,v in m.headers.items() if k.lower() not in ('content-type','content-length')}
        return machine.post(path,m.body,content_type='application/json',HTTP_HOST='registry.example.test',**headers)
    report={'version':1,'hostname':'demo-host'}
    result=signed('/api/hosts/enrollment/',{'public_key':signatures.public_text(key.public_key()),'claimed_host_id':'','report':report},'pending')
    assert result.status_code==202;print('1. Proof-of-possession enrollment: pending, no trusted host or archive token')
    def decision(data):
        r=administrator.post('/api/hosts/identities/decision/',json.dumps(data),content_type='application/json');assert r.status_code==200;return r.json()
    host=decision({'action':'approve','fingerprint':fingerprint,'confirmed_fingerprint':fingerprint})['host_id']
    print('2. Administrator approved exact fingerprint:',fingerprint)
    first=signed('/api/hosts/'+host+'/heartbeat/',report,host);assert first.status_code==200 and first.json()['archive'] is None
    print('3. Signed heartbeat accepted; approval alone grants no archive access')
    decision({'action':'policy','host_id':host,'operations':['download'],'collections':['sources']})
    result=signed('/api/hosts/'+host+'/heartbeat/',report,host);assert result.status_code==200
    grant=result.json()['archive'];print('4. Separate policy issued 15-minute host token (token omitted)')
    from zog.archive_mirror.store import publish
    from zog.archive_mirror.runtime import atomic
    import base64,io,tarfile,time
    intent=Path(directory)/'intent.json'
    intent.write_text(json.dumps({'version':1,'host_id':host,'desired':{'version':1,'selected':True,'revision':1,'endpoint':'https://mirror.example.test','lease_expires_at':int(time.time())+900}}));intent.chmod(0o640)
    public=Path(directory)/'public.json';public.write_text(json.dumps({'version':1,'keys':{'demo':signatures.public_text(issuer.public_key())}}))
    Path(os.environ['ARCHIVE_MIRROR_CONFIGURATION']).write_text(json.dumps({'root':str(Path(directory)/'store'),'collections':['sources','root-filesystems'],'host_id':host,'intent_file':str(intent),'endpoint':'https://mirror.example.test','keyring':str(public),'issuer':origin,'audience':'mirror-demo'}))
    archive=Path(directory)/'source.tar.xz'
    with tarfile.open(archive,'w:xz') as output:
        member=tarfile.TarInfo('example/source');member.size=4;output.addfile(member,io.BytesIO(b'test'))
    record=publish(archive,'sources','source',{'fixture':True})
    result=machine.get('/collections/sources/archives/'+record.digest+'.tar.xz',HTTP_AUTHORIZATION='Bearer '+grant['token'])
    assert result.status_code==200 and b''.join(result.streaming_content)==archive.read_bytes()
    assert machine.get('/collections/sources/',HTTP_AUTHORIZATION='Bearer '+grant['token']).status_code==403
    assert machine.get('/collections/root-filesystems/archives/'+record.digest+'.tar.xz',HTTP_AUTHORIZATION='Bearer '+grant['token']).status_code==403
    assert administrator.get('/archives/').status_code==200
    print('5. Actual archive app: exact downloaded bytes; denied list/other collection; administrator catalogue works')
    decision({'action':'policy','host_id':host,'operations':[],'collections':[]})
    assert signed('/api/hosts/'+host+'/heartbeat/',report,host).json()['archive'] is None
    print('6. Explicit policy withdrawal removes new grant; existing token expiry remains bounded by issuer contract')
    print('PASS: isolated station-access signed enrollment -> approval -> heartbeat grant -> real archive Django download')
