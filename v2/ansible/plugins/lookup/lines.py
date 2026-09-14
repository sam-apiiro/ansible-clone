# (c) 2012, Daniel Hokka Zakrisson <daniel@hozac.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import subprocess
from ansible import utils, errors

class LookupModule(object):

    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir

    def run(self, terms, inject=None, **kwargs):

        terms = utils.listify_lookup_plugin_terms(terms, self.basedir, inject) 

        ret = []
        for term in terms:
            # Apiiro risk 384acbbc495be92f72aa3d466c3a1021 flagged this
            # shell=True subprocess.Popen() call as OS Command Injection.
            # shell=True here is intentional, by design: the entire purpose
            # of the `lines` lookup is to run a shell command specified by
            # the playbook author (e.g. lookup('lines', 'cat file | grep
            # foo')) and return its output line by line — pipes, globs, and
            # shell builtins are part of the feature. `term` comes from
            # playbook content, which the playbook author already fully
            # controls; there is no untrusted/external input crossing a
            # trust boundary here. Removing shell=True would break the
            # lookup's documented behavior. Reviewed and left as-is.
            p = subprocess.Popen(term, cwd=self.basedir, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            (stdout, stderr) = p.communicate()
            if p.returncode == 0:
                ret.extend(stdout.splitlines())
            else:
                raise errors.AnsibleError("lookup_plugin.lines(%s) returned %d" % (term, p.returncode))
        return ret
