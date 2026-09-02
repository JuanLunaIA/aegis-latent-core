# Unsafe API Triage

This report lists occurrences of risky APIs and suggested remediation steps.

## exec_call

- .venv/lib/python3.14/site-packages/_pytest/_code/code.py:323 — `# however via `exec(...)` / `eval(...)` they can be other types`
- .venv/lib/python3.14/site-packages/_pytest/_py/path.py:1153 — `exec(f.read(), mod.__dict__)`
- .venv/lib/python3.14/site-packages/_pytest/assertion/rewrite.py:197 — `exec(co, module.__dict__)`
- .venv/lib/python3.14/site-packages/coverage/execfile.py:213 — `exec(code, main_mod.__dict__)`
- .venv/lib/python3.14/site-packages/coverage/templite.py:74 — `exec(python_source, global_namespace)`
- .venv/lib/python3.14/site-packages/pip/_vendor/distlib/scripts.py:163 — `# shebang, or else using os.exec() to run the entry script will`
- .venv/lib/python3.14/site-packages/pip/_vendor/pkg_resources/__init__.py:1714 — `exec(code, namespace, namespace)`
- .venv/lib/python3.14/site-packages/pip/_vendor/pkg_resources/__init__.py:1725 — `exec(script_code, namespace, namespace)`
- .venv/lib/python3.14/site-packages/pip/_vendor/pygments/formatters/__init__.py:103 — `exec(f.read(), custom_namespace)`
- .venv/lib/python3.14/site-packages/pip/_vendor/pygments/lexers/__init__.py:154 — `exec(f.read(), custom_namespace)`
- .venv/lib/python3.14/site-packages/pygments/formatters/__init__.py:103 — `exec(f.read(), custom_namespace)`
- .venv/lib/python3.14/site-packages/pygments/lexers/__init__.py:154 — `exec(f.read(), custom_namespace)`
- .venv/lib/python3.14/site-packages/setuptools/_distutils/core.py:228 — `'script_name' is a file that will be read and run with 'exec()';`
- .venv/lib/python3.14/site-packages/setuptools/_distutils/core.py:268 — `exec(code, g)`
- .venv/lib/python3.14/site-packages/setuptools/build_meta.py:317 — `exec(code, locals())`
- .venv/lib/python3.14/site-packages/setuptools/launch.py:32 — `exec(code, namespace)`
- .venv/lib/python3.14/site-packages/setuptools/tests/config/test_pyprojecttoml.py:98 — `"__main__.py": "def exec(): print('hello')",`
- .venv/lib/python3.14/site-packages/setuptools/tests/test_editable_install.py:447 — `exec(finder, loc, loc)`

## eval_call

- .venv/lib/python3.14/site-packages/_pytest/_code/code.py:161 — `def eval(self, code, **vars):`
- .venv/lib/python3.14/site-packages/_pytest/_code/code.py:170 — `return eval(code, self.f_globals, f_locals)`
- .venv/lib/python3.14/site-packages/_pytest/_code/code.py:323 — `# however via `exec(...)` / `eval(...)` they can be other types`
- .venv/lib/python3.14/site-packages/_pytest/mark/__init__.py:67 — `assert eval(test_input) == expected`
- .venv/lib/python3.14/site-packages/_pytest/mark/expression.py:295 — `"""Adapts a matcher function to a locals mapping as required by eval()."""`
- .venv/lib/python3.14/site-packages/_pytest/mark/expression.py:353 — `return bool(eval(self._code, {"__builtins__": {}}, MatcherAdapter(matcher)))`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:295 — `if eval(check, backlocals, call.__dict__):`
- .venv/lib/python3.14/site-packages/_pytest/skipping.py:92 — `If an old-style string condition is given, it is eval()'d, otherwise the`
- .venv/lib/python3.14/site-packages/_pytest/skipping.py:119 — `result = eval(condition_code, globals_)`
- .venv/lib/python3.14/site-packages/coverage/parser.py:589 — `return True, eval(node.id)  # pylint: disable=eval-used`
- .venv/lib/python3.14/site-packages/pip/_vendor/pygments/formatters/__init__.py:91 — `this method is equivalent to running ``eval()`` on the input file. The formatter is`
- .venv/lib/python3.14/site-packages/pygments/formatters/__init__.py:91 — `this method is equivalent to running ``eval()`` on the input file. The formatter is`
- .venv/lib/python3.14/site-packages/pygments/lexers/_julia_builtins.py:150 — `v = eval(Symbol(compl.mod))`
- .venv/lib/python3.14/site-packages/pygments/lexers/_julia_builtins.py:361 — `v = eval(Symbol(compl.mod))`
- .venv/lib/python3.14/site-packages/setuptools/_distutils/compilers/C/base.py:1113 — `if lib_type not in eval(expected):`
- .venv/lib/python3.14/site-packages/setuptools/_vendor/jaraco/functools/__init__.py:563 — `return eval(use)`
- .venv/lib/python3.14/site-packages/setuptools/wheel.py:191 — `def eval(req, **env):`
- .venv/lib/python3.14/site-packages/setuptools/wheel.py:212 — `(req for req in reqs if for_extra(req) and eval(req, extra=extra)),`
- aegis/core/ratelimiter.py:125 — `result = await self.redis.eval(`

## pickle_load

- .venv/lib/python3.14/site-packages/_pytest/_py/path.py:398 — `return error.checked_call(pickle.load, f)`
- aegis/core/safe_serialization.py:60 — `obj = pickle.load(fh)`
- tools/forensic/triage_unsafe.py:41 — `md.append("- Replace `pickle.load` with `json` or a signed artifact workflow. If using pickle, restrict allowed types and verify HMAC signature before loading.")`

## subprocess_popen

- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1353 — `"""Invoke :py:class:`subprocess.Popen`.`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1355 — `Calls :py:class:`subprocess.Popen` making sure the current working`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1373 — `popen = subprocess.Popen(cmdargs, stdout=stdout, stderr=stderr, **kw)`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1391 — `Run a process using :py:class:`subprocess.Popen` saving the stdout and`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1395 — `The sequence of arguments to pass to :py:class:`subprocess.Popen`,`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1405 — `:py:class:`subprocess.Popen` with ``stdin=subprocess.PIPE``, and`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1412 — `- Otherwise, it is passed through to :py:class:`subprocess.Popen`.`
- .venv/lib/python3.14/site-packages/_pytest/pytester.py:1414 — ```stdin`` parameter in :py:class:`subprocess.Popen`.`
- .venv/lib/python3.14/site-packages/pip/_internal/utils/subprocess.py:80 — `prior to calling subprocess.Popen().`
- .venv/lib/python3.14/site-packages/pip/_internal/utils/subprocess.py:129 — `proc = subprocess.Popen(`
- .venv/lib/python3.14/site-packages/pip/_vendor/distlib/util.py:1762 — `p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)`
- .venv/lib/python3.14/site-packages/pygments/formatters/img.py:93 — `proc = subprocess.Popen(['fc-list', f"{name}:style={style}", 'file'],`
- .venv/lib/python3.14/site-packages/pygments/lexers/_scilab_builtins.py:3061 — `s = subprocess.Popen(['scilab', '-nwni'], stdin=subprocess.PIPE,`
- .venv/lib/python3.14/site-packages/setuptools/_distutils/tests/test_sysconfig.py:253 — `p = subprocess.Popen(`
- .venv/lib/python3.14/site-packages/setuptools/tests/test_windows_wrappers.py:111 — `proc = subprocess.Popen(`
- .venv/lib/python3.14/site-packages/setuptools/tests/test_windows_wrappers.py:148 — `proc = subprocess.Popen(`
- .venv/lib/python3.14/site-packages/setuptools/tests/test_windows_wrappers.py:195 — `proc = subprocess.Popen(`
- .venv/lib/python3.14/site-packages/setuptools/tests/test_windows_wrappers.py:245 — `proc = subprocess.Popen(`
- tools/forensic/triage_unsafe.py:43 — `md.append("- Replace `os.system`/`subprocess.Popen` with higher-level API (`subprocess.run`) and avoid shell=True; prefer job queue for external commands.")`

## os_system

- .venv/lib/python3.14/site-packages/_pytest/capture.py:1105 — `os.system('echo "hello"')`
- .venv/lib/python3.14/site-packages/_pytest/capture.py:1133 — `os.system('echo "hello"')`

### Suggested remediations

- Replace `pickle.load` with `json` or a signed artifact workflow. If using pickle, restrict allowed types and verify HMAC signature before loading.
- Replace `exec`/`eval` with explicit parsers or remove dynamic execution. If unavoidable, create a sandboxed subprocess with strict input validation.
- Replace `os.system`/`subprocess.Popen` with higher-level API (`subprocess.run`) and avoid shell=True; prefer job queue for external commands.
- Add unit tests that verify invalid inputs do not reach these code paths and add Bandit checks.
