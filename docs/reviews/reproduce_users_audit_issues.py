"""Isolated checks. No lifespan, runner worker, scheduler, Strix, or provider calls."""
import os,sys,json,tempfile
from pathlib import Path
from unittest import mock
from datetime import datetime,timezone
os.environ['SKYNET_LOAD_DOTENV']='0'
os.environ.pop('SKYNET_SECRET_KEY',None)
os.environ['SKYNET_PASSWORD']='review-only-admin-password'
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from test_users_audit import Base
from skynet import auth,db,vault,report,main,crypto,audit
b=Base();b.setUp();admin=b.user('admin');analyst=b.user('analyst');viewer=b.user('viewer')
out={}
# Check whether an agent name containing a current Vault secret reaches audit storage/API.
secret='review-vault-only-7c53eab02'
vault.save({'kind':'header','name':'Review credential','headers':[{'name':'Authorization','value':'Bearer '+secret}]},None)
with tempfile.TemporaryDirectory(prefix='skynet-audit-repro-') as d:
    rd=Path(d);(rd/'.state').mkdir()
    (rd/'.state/agents.json').write_text(json.dumps({'statuses':{'review-agent':'running'},'names':{'review-agent':'Agent '+secret}}))
    tid=db.insert('targets',{'name':'Review local target','environment':'test','base_url':'http://127.0.0.1:8899'})
    sid=db.insert('scans',{'target_id':tid,'status':'running','run_name':rd.name,'run_dir':str(rd)})
    mid=db.insert('agent_messages',{'scan_id':sid,'request_id':'audit-review-1','agent_id':'review-agent','content_enc':crypto.vault_encrypt('instruction')})
    with mock.patch.object(main.control,'send',return_value={'id':mid}):
        st,body=b.call(f'/api/scans/{sid}/messages','POST',{'agent_id':'review-agent','content':'review instruction'},user=analyst)
    row=db.q1("SELECT * FROM audit_log WHERE action='agent.instruct' ORDER BY id DESC LIMIT 1")
    out['audit_secret']={'http_status':st,'known_secret_in_audit_database':secret in json.dumps(row),'known_secret_in_audit_api':secret in json.dumps(audit.entries()),'normal_scan_redactor_masks_it':secret not in vault.scan_redactor(db.get_scan(sid)).text('Agent '+secret,strict=True)}
# Check the old session after disable/re-enable, without a new login.
u=b.user('analyst');cookie=auth.make_session(u)
auth.update_user(u['id'],admin,active=False)
disabled=b.call('/api/me',cookie=cookie)[0]
auth.update_user(u['id'],admin,active=True)
reactivated=b.call('/api/me',cookie=cookie)[0]
out['old_session_after_reenable']={'while_disabled':disabled,'same_old_cookie_after_reenable':reactivated}
# Compare time-to-fix before/after editing only the note of an already-fixed finding.
tid=db.insert('targets',{'name':'Report timing fixture','environment':'test','base_url':'http://127.0.0.1:8899'})
sid=db.insert('scans',{'target_id':tid,'status':'completed','trigger':'manual','started_at':'2026-01-01T00:00:00+00:00'})
gid=db.insert('finding_groups',{'target_id':tid,'fingerprint':'review-fixed','title':'Review finding','severity':'high','remediation':'fixed','first_seen_at':'2026-01-01T00:00:00+00:00','remediation_at':'2026-01-02T00:00:00+00:00','fixed_at':'2026-01-02T00:00:00+00:00'})
db.insert('finding_occurrences',{'group_id':gid,'scan_id':sid,'run_name':'review-report-time','strix_id':'v1','severity':'high','observed_at':'2026-01-01T00:00:00+00:00'})
before=report.for_target(tid)['findings']['time_to_fix']['high']['median']
with mock.patch.object(db,'now_iso',return_value='2026-01-10T00:00:00+00:00'):
    st,_=b.call(f'/api/findings/{gid}','PATCH',{'remediation':'fixed','remediation_note':'Only updating the ticket note'},user=analyst)
after=report.for_target(tid)['findings']['time_to_fix']['high']['median']
out['time_to_fix_note_edit']={'http_status':st,'before_days':before,'after_days':after,'status_stayed_fixed':db.get('finding_groups',gid)['remediation']=='fixed'}
# Target report metadata returns a matching known secret without masking it.
# No network endpoint is called; this is the normal target-report GET on a fixture.
db.execute('UPDATE targets SET name=? WHERE id=?',('Target '+secret,tid))
st,data=b.call(f'/api/targets/{tid}/report',user=viewer)
out['report_metadata_secret']={'http_status':st,'known_secret_in_report':secret in json.dumps(data)}
print(json.dumps(out,indent=2))

# Remove only the test module's own temporary data/key directory.
import shutil,test_features
if db._conn is not None:
    db._conn.close();db._conn=None
shutil.rmtree(test_features._TMP)
