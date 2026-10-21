"""Three real server SIGKILL/restart cases, restricted to labelled CI container."""
import json
import os
import subprocess
import time
from test_persistent_candidate import IntegrationTests

class ServerCrashTests(IntegrationTests):
    # Retain parent helpers but prevent inherited duplicate test discovery below.
    def restart_server(self):
        if os.environ.get('SYNTHETIC_CI_CONTAINER') != 'synthetic-edit-mongo':
            raise RuntimeError('Real crash tests require explicitly labelled disposable CI container')
        name='synthetic-edit-mongo'
        data=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
        if data['Config'].get('Labels',{}).get('purpose')!='synthetic-edit-tests':
            raise RuntimeError('Refusing to kill any non-test container')
        subprocess.run(['docker','kill','--signal=KILL',name],check=True,capture_output=True)
        subprocess.run(['docker','start',name],check=True,capture_output=True)
        for _ in range(30):
            try:
                if self.a.client.admin.command('hello').get('isWritablePrimary'):return
            except Exception:pass
            time.sleep(.3)
        raise RuntimeError('Test server did not recover')
    def server_case(self,stage,committed):
        p,t=self.proposal()
        def hook(s):
            if s==stage:
                self.restart_server()
                raise RuntimeError('simulated response loss across actual server crash')
        with self.assertRaises(RuntimeError):self.a.commit(p,'fixture-client',t,hook)
        if committed:self.assert_committed(t)
        else:
            self.assertEqual(self.state(),'old')
            self.assertEqual(self.a.db.receipts.count_documents({}),0)
            self.assertEqual(self.a.reconcile(t),'abandoned')
    def test_server_crash_reserved(self):self.server_case('after_reservation',False)
    def test_server_crash_uncommitted_transaction(self):self.server_case('after_edit',False)
    def test_server_crash_committed_before_response(self):self.server_case('after_commit',True)

# Explicit load avoids rerunning inherited tests and imported IntegrationTests.
def load_tests(loader, tests, pattern):
    import unittest
    return unittest.TestSuite(ServerCrashTests(name) for name in (
        'test_server_crash_reserved','test_server_crash_uncommitted_transaction',
        'test_server_crash_committed_before_response'))
