"""Validate literal ENV request keys against the inspected provider schema.

Source: coollabsio/coolify commit378ce3735c4522ebb6b68e93b909b0511f278763,
app/Http/Controllers/Api/ApplicationsController.php create_env, lines4655–4694.
Unknown fields are rejected422. This intentionally inspects the actual request
call without executing the disposable-runner-only module or sending a request.
"""
import ast
import pathlib
import unittest

CREATE_ENV_FIELDS={'key','value','is_preview','is_literal','is_multiline',
                   'is_shown_once','is_runtime','is_buildtime','comment'}

class ProviderSchemaTests(unittest.TestCase):
    def test_actual_env_request_conforms_to_pinned_provider_allowed_fields(self):
        tree=ast.parse(pathlib.Path(__file__).with_name('native_revisions.py').read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
               and isinstance(n.func,ast.Name) and n.func.id=='api' and len(n.args)==3
               and isinstance(n.args[0],ast.BinOp)
               and isinstance(n.args[0].right,ast.Constant) and n.args[0].right.value=='/envs']
        self.assertEqual(len(calls),1)
        request=calls[0].args[2]
        self.assertIsInstance(request,ast.Dict)
        keys={ast.literal_eval(k) for k in request.keys}
        self.assertTrue(keys<=CREATE_ENV_FIELDS,keys-CREATE_ENV_FIELDS)
        self.assertTrue({'key','value'}<=keys)

    def test_previous_spelling_is_rejected_by_vendor_schema(self):
        self.assertNotIn('is_build_time',CREATE_ENV_FIELDS)
