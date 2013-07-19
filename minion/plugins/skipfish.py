# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import ast
import logging
import os
import re
import subprocess
import shutil

from minion.plugins.base import ExternalProcessPlugin


# Name of the skipfish binary
SKIPFISH_TOOL_NAME = "skipfish"

# Min version of skipfish that we support
SKIPFISH_MIN_VERSION = "2.02"

# Max version of skipfish that we support
SKIPFISH_MAX_VERSION = "2.10"

# Name of the file where stdout is written
SKIPFISH_STDOUT_LOG = "skipfish.stdout.txt"

# Name of the file where stderr is written
SKIPFISH_STDERR_LOG = "skipfish.stderr.txt"

# Name of the dictionary that we use in our work directory
SKIPFISH_DICTIONARY = "dictionary.wl"

# Paths where we look for skipfish dictionaries (currently just following Debian/Ubuntu)
SKIPFISH_DICTIONARY_PATHS = ["/usr/share/skipfish/dictionaries"]

# Name of the directory where the report is written
SKIPFISH_REPORT_DIRECTORY = 'report'

# Name of the file that contains the issues/samples
SKIPFISH_SAMPLES_JS = "samples.js"

# Standard options that all presets use
SKIPFISH_BASE_OPTIONS = ['-M', '-E', '-U', '-u', '-o', SKIPFISH_REPORT_DIRECTORY]

# Built-in presets based on the skipfish documentation
SKIPFISH_PRESETS = {
    # 1. Orderly crawl with no dirbuster-like brute-force at all
    #    skipfish -W /dev/null -LV
    'fast-orderly-scan': {
        'options': ['-L', '-V'],
        'dictionary': '/dev/null'
    },
    # 2. Orderly scan with minimal extension brute-force.
    #    cp dictionaries/extensions-only.wl dictionary.wl
    #    skipfish -W dictionary.wl -Y
    'orderly-scan-with-extensions-only-brute-force': {
        'options': ['-Y'],
        'dictionary': 'extensions-only.wl'
    },
    # 3. Directory OR extension brute-force only.
    #    cp dictionaries/complete.wl dictionary.wl
    #    skipfish -W dictionary.wl -Y
    'brute-force': {
        'options': ['-Y'],
        'dictionary': 'complete.wl'
    },
    # 4. Normal dictionary fuzzing.
    #    cp dictionaries/XXX.wl dictionary.wl (minimal, medium, complete)
    #    ./skipfish -W dictionary.wl
    'minimal-fuzzing': {
        'options': [],
        'dictionary': 'minimal.wl'
    },
    'medium-fuzzing': {
        'options': [],
        'dictionary': 'medium.wl'
    },
    'complete-fuzzing': {
        'options': [],
        'dictionary': 'complete.wl'
    }
}

# If not preset is specified we run a somewhat gentle scan
SKIPFISH_DEFAULT_PRESET = 'orderly-scan-with-extensions-only-brute-force'

# Mapping from skipfish issue number to what Minion issues expect
SKIPFISH_ISSUE_SEVERITY = ['Info', 'Error', 'Low', 'Medium', 'High']

# Mappings from skipfish issue types to descriptions
SKIPFISH_ISSUE_DESCRIPTIONS = {
  10101: "SSL certificate issuer information",
  10102: "SSL cert will expire",

  10201: "New HTTP cookie added",
  10202: "New 'Server' header value seen",
  10203: "New 'Via' header value seen",
  10204: "New 'X-*' header value seen",
  10205: "New 404 signature seen",

  10401: "Resource not directly accessible",
  10402: "HTTP authentication required",
  10403: "Server error triggered",
  10404: "Directory listing found",
  10405: "Hidden resource found",

  10501: "All external links",
  10502: "External URL redirector",
  10503: "All e-mail addresses",
  10504: "Links to unknown protocols",
  10505: "Unknown form field (can't autocomplete)",

  10601: "HTML form (not classified otherwise)",
  10602: "Password entry form - consider brute-force",
  10603: "File upload form",

  10701: "User-supplied link rendered on a page",

  10801: "Incorrect or missing MIME type (low risk)",
  10802: "Generic MIME used (low risk)",
  10803: "Incorrect or missing charset (low risk)",
  10804: "Conflicting MIME / charset info (low risk)",

  10901: "Numerical filename - consider enumerating",
  10902: "OGNL-like parameter behavior",

  10909: "Signature detected info",

  20101: "Resource fetch failed",
  20102: "Limits exceeded, fetch suppressed",

  20201: "Directory behavior checks failed (no brute force)",
  20202: "Parent behavior checks failed (no brute force)",
  20203: "IPS filtering enabled",
  20204: "IPS filtering disabled again",
  20205: "Response varies randomly, skipping checks",

  20301: "Node should be a directory, detection error?",

  30101: "HTTP credentials seen in URLs",

  30201: "SSL certificate expired or not yet valid",
  30202: "Self-signed SSL certificate",
  30203: "SSL certificate host name mismatch",
  30204: "No SSL certificate data found",
  30205: "Weak cipher negotiated",
  30206: "Possible \0 in host name",

  30301: "Directory listing restrictions bypassed",

  30401: "Redirection to attacker-supplied URLs",
  30402: "Attacker-supplied URLs in embedded content (lower risk)",

  30501: "External content embedded on a page (lower risk)",
  30502: "Mixed content embedded on a page (lower risk)",
  30503: "HTTPS -> HTTP form",

  30601: "HTML form with no apparent XSRF protection",
  30602: "JSON response with no apparent XSSI protection",

  30701: "Incorrect caching directives (lower risk)",

  30801: "User-controlled response prefix (BOM / plugin attacks)",
  30802: "XSS vector, lower risk",

  30901: "Injected string in header",

  30909: "Signature detected low",

  40101: "XSS vector in document body",
  40102: "XSS vector via arbitrary URLs",
  40103: "HTTP response header splitting",
  40104: "Attacker-supplied URLs in embedded content (higher risk)",
  40105: "TAG attribute XSS",

  40201: "External content embedded on a page (higher risk)",
  40202: "Mixed content embedded on a page (higher risk)",

  40301: "Incorrect or missing MIME type (higher risk)",
  40302: "Generic MIME type (higher risk)",
  40304: "Incorrect or missing charset (higher risk)",
  40305: "Conflicting MIME / charset info (higher risk)",

  40401: "Interesting file",
  40402: "Interesting server message",

  40501: "Directory traversal / file inclusion possible",

  40601: "Incorrect caching directives (higher risk)",

  40701: "Password form submits from or to non-HTTPS page",

  40909: "Signature detected moderate",

  50101: "Server-side XML injection vector",
  50102: "Shell injection vector",
  50103: "Query injection vector",
  50104: "Format string vector",
  50105: "Integer overflow vector",
  50106: "Local file inclusion",
  50107: "Remote file inclusion",

  50201: "SQL query or similar syntax in parameters",

  50301: "PUT request accepted",

  50909: "Signature detected high",
}

class SkipfishPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "Skipfish"
    PLUGIN_VERSION = "0.2"

    def _skipfish_version(self, path):
        version = None
        p = subprocess.Popen([path, "-h"], stdout=subprocess.PIPE, bufsize=0)
        for line in p.stdout:
            m = re.match(".*version (\\d+\.\\d+)b", line)
            if m is not None:
                version = m.group(1)
                break
        p.terminate()
        return version

    def _process_skipfish_samples(self, samples_path):
        # The samples.js file needs to be tranformed into something
        # that we can parse more easily. So we turn it into a Python
        # dictionary with some string replacements and then let the
        # AST module parse it in a safe way that does not allow code
        # execution.. TODO This is dependend on the specific skipfish
        # version so we should probably pin it down somehow.
        with open(samples_path) as f:
            samples = f.read()
            samples = samples.replace("'", '"')
            samples = samples.replace('var mime_samples =', '"mime_samples":')
            samples = samples.replace('];', '],', 1)
            samples = samples.replace('var issue_samples =', '"issue_samples":')
            samples = samples.replace('];', ']', 1)
            samples = '{\n' + samples + '}'
            return ast.literal_eval(samples)
        
    def _locate_dictionary(self, dictionary_name):
        # Special case for /dev/null
        if os.path.isabs(dictionary_name):
            return dictionary_name
        # Look for the dictionary in all the paths that we know about
        for dictionary_base_path in SKIPFISH_DICTIONARY_PATHS:
            path = os.path.join(dictionary_base_path, dictionary_name)
            if os.path.exists(path):
                return path

    def do_start(self):
        # Find the skipfish binary on the PATH
        skipfish_path = self.locate_program(SKIPFISH_TOOL_NAME)
        if skipfish_path is None:
            path = os.environ['PATH']
            raise Exception("Cannot find (%s) in PATH (%s)" % (SKIPFISH_TOOL_NAME,path))
        skipfish_version = self._skipfish_version(skipfish_path)
        if skipfish_version is None:
            raise Exception("Unable to discover the version of Skipfish at " + skipfish_path)
        if skipfish_version < SKIPFISH_MIN_VERSION or skipfish_version > SKIPFISH_MAX_VERSION:
            raise Exception("Unknown Skipfish version. We only support %sb - %sb" % (SKIPFISH_MIN_VERSION, SKIPFISH_MAX_VERSION))
        # See if a good preset was specified, or use our default
        preset = self.configuration.get('preset') or SKIPFISH_DEFAULT_PRESET
        if preset not in SKIPFISH_PRESETS:
            raise Exception("Invalid preset specified (%s)" % preset)
        config = SKIPFISH_PRESETS[preset]
        # Find the dictionary that we need
        dictionary_path = self._locate_dictionary(config['dictionary'])
        if dictionary_path is None:
            raise Exception("Cannot find dictionary (%s)" % config['dictionary'])
        # Copy the dictionary to our work directory as dictionary.wl
        shutil.copyfile(dictionary_path, SKIPFISH_DICTIONARY)
        # Run skipfish as a spawned process
        args = SKIPFISH_BASE_OPTIONS
        args += config['options']
        if skipfish_version >= "2.04":
            args += ["-W", "/dev/null", "-S", SKIPFISH_DICTIONARY]
        else:
            args += ["-W", SKIPFISH_DICTIONARY]

        auth = self.configuration.get('auth')
        if auth:
            auth_type = auth['type']
            if auth_type == 'basic':
                args += ["-A", "%s:%s" % (auth['username'], auth['password'])]
            elif auth_type == 'session':
                # reject any new cookie created
                # see http://code.google.com/p/skipfish/wiki/Authentication#Cookie_authentication
                if auth.get('no-new-cookie', True):
                    cookie_args = ['-N']
                else:
                    cookie_args = []
                for session in auth.get('sessions'):
                    cookie_args += ["-C", '%s=%s' % (session['token'], session['value'])]
                args += cookie_args

        args += [self.configuration['target']]
        self.skipfish_stdout = ""
        self.skipfish_stderr = ""
        self.spawn(skipfish_path, args)

    def do_process_stdout(self, data):
        self.skipfish_stdout += data

    def do_process_stderr(self, data):
        self.skipfish_stderr += data

    def do_process_ended(self, status):
        # Always stdout and stderr
        with open(SKIPFISH_STDOUT_LOG, "w") as f:
            f.write(self.skipfish_stdout)
        with open(SKIPFISH_STDERR_LOG, "w") as f:
            f.write(self.skipfish_stderr)
        self.report_artifacts("Skipfish Output", [SKIPFISH_STDOUT_LOG, SKIPFISH_STDERR_LOG])
        # Depending on our exit status we are stopped or finished
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            samples_path = os.path.join(SKIPFISH_REPORT_DIRECTORY, SKIPFISH_SAMPLES_JS)
            if os.path.exists(samples_path):
                minion_issues = []
                samples = self._process_skipfish_samples(samples_path)
                for issue in samples.get('issue_samples'):
                    i = { "Severity": SKIPFISH_ISSUE_SEVERITY[issue['severity']],
                          "Summary": SKIPFISH_ISSUE_DESCRIPTIONS.get(issue['type'], str(issue['type'])),
                          "URLs": [] } # s['url'] for s in issue['samples']] }
                    for sample in issue.get('samples', []):
                        if sample.get('url', '') != '':
                            url = { 'URL': sample['url'] }
                            if sample.get('extra', '') != '':
                                url['Extra'] = sample.get('extra')
                            i['URLs'].append(url)
                    minion_issues.append(i)
                self.report_issues(minion_issues)
                # Add the report and the (updated) dictionary to the artifacts
                self.report_artifacts("Skipfish Report", [SKIPFISH_REPORT_DIRECTORY])
                self.report_artifacts("Skipfish Dictionary", [SKIPFISH_DICTIONARY])
            self.report_finish()
        else:
            self.report_finish("FAILED")
