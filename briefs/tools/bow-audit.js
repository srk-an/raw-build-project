/* BOW Review Auditor — rule engine.
   Pure JS (no DOM). Runs in the browser (window.BowAudit) and in Node (module.exports).
   Input: the unzipped contents of a Workday Extend Studio export.
   Output: findings shaped like the Workday "Build Review" sheet. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.BowAudit = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ---------------------------------------------------------------- *
   * Lenient JSON parser with line tracking.
   * PMD files are not strict JSON: "script" values hold raw newlines.
   * ---------------------------------------------------------------- */
  function parseLenient(text) {
    var i = 0, line = 1, n = text.length, badEscapes = [];
    function fail(msg) { var e = new Error(msg + ' (line ' + line + ')'); e.line = line; throw e; }
    function ws() {
      while (i < n) {
        var c = text.charCodeAt(i);
        if (c === 10) { line++; i++; }
        else if (c === 32 || c === 9 || c === 13 || c === 0xFEFF) i++;
        else break;
      }
    }
    function str() {
      var startLine = line, out = '';
      i++;
      while (i < n) {
        var c = text[i];
        if (c === '"') { i++; return out; }
        if (c === '\\') {
          var d = text[i + 1];
          if (d === 'n') out += '\n';
          else if (d === 't') out += '\t';
          else if (d === 'r') out += '\r';
          else if (d === 'b') out += '\b';
          else if (d === 'f') out += '\f';
          else if (d === 'u') { out += String.fromCharCode(parseInt(text.substr(i + 2, 4), 16)); i += 6; continue; }
          else if (d === "'") { badEscapes.push(line); out += "'"; }
          else out += d;
          i += 2;
          continue;
        }
        if (c === '\n') line++;
        out += c;
        i++;
      }
      fail('Unterminated string that starts on line ' + startLine);
    }
    function hide(o, name, val) { Object.defineProperty(o, name, { value: val, enumerable: false }); }
    function obj() {
      var o = {}, keyLines = {};
      hide(o, '__line', line);
      hide(o, '__keyLines', keyLines);
      i++;
      for (;;) {
        ws();
        if (text[i] === '}') { i++; break; }
        if (text[i] !== '"') fail('Expected a property name');
        var kl = line, k = str();
        ws();
        if (text[i] !== ':') fail('Expected ":" after property name');
        i++; ws();
        o[k] = val();
        keyLines[k] = kl;
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; break; }
        fail('Expected "," or "}"');
      }
      return o;
    }
    function arr() {
      var a = [];
      hide(a, '__line', line);
      i++;
      for (;;) {
        ws();
        if (text[i] === ']') { i++; break; }
        a.push(val());
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; break; }
        fail('Expected "," or "]"');
      }
      return a;
    }
    function val() {
      ws();
      var c = text[i];
      if (c === '{') return obj();
      if (c === '[') return arr();
      if (c === '"') return str();
      var m = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 40));
      if (!m) fail('Unexpected character "' + (c || 'end of file') + '"');
      i += m[0].length;
      return m[0] === 'true' ? true : m[0] === 'false' ? false : m[0] === 'null' ? null : Number(m[0]);
    }
    try {
      ws();
      var value = val();
      ws();
      if (i < n) fail('Unexpected content after the end of the JSON value');
      return { value: value, badEscapes: badEscapes, error: null };
    } catch (e) {
      return { value: null, badEscapes: badEscapes, error: e };
    }
  }

  function walk(node, fn, key, parent) {
    if (node && typeof node === 'object') {
      fn(node, key, parent);
      if (Array.isArray(node)) node.forEach(function (c, ix) { walk(c, fn, ix, node); });
      else Object.keys(node).forEach(function (k) { walk(node[k], fn, k, node); });
    }
  }

  function walkStrings(node, fn) {
    if (typeof node === 'string') fn(node);
    else if (node && typeof node === 'object') Object.keys(node).forEach(function (k) { walkStrings(node[k], fn); });
  }

  /* ------------------------------ helpers ------------------------------ */
  function baseName(p) { return p.split('/').pop(); }
  function extOf(p) { var m = /\.([A-Za-z0-9]+)$/.exec(baseName(p)); return m ? m[1].toLowerCase() : ''; }
  function stem(p) { return baseName(p).replace(/\.[^.]+$/, ''); }
  function lineOfIndex(text, idx) { var c = 1; for (var k = 0; k < idx; k++) if (text.charCodeAt(k) === 10) c++; return c; }
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function countWord(hay, word) { var m = hay.match(new RegExp('(^|[^A-Za-z0-9_$])' + esc(word) + '(?![A-Za-z0-9_$])', 'g')); return m ? m.length : 0; }
  function tagName(type) { return type ? type.charAt(0).toUpperCase() + type.slice(1) + 'Tag' : 'Tag'; }
  function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }

  var TEXT_EXT = { pmd: 1, pod: 1, card: 1, script: 1, amd: 1, smd: 1, attributes: 1, businessobject: 1, attachment: 1, securitydomain: 1, orchestration: 1, task: 1, json: 1, businessprocess: 1 };

  /* ------------------------------ rule catalogue ------------------------------ */
  var RULES = [
    { id: 'S1', area: 'Security', title: 'App security domains are enabled for page and orchestration security' },
    { id: 'S2', area: 'Security', title: 'Every PMD declares securityDomains' },
    { id: 'S3', area: 'Security', title: 'Every orchestration has a security domain' },
    { id: 'S4', area: 'Security', title: 'Business objects have a default security domain; contextual security considered' },
    { id: 'S5', area: 'Security', title: 'Security domain names do not match business object names' },
    { id: 'S6', area: 'Security', title: 'Security domains are named after the app; queries match' },
    { id: 'S7', area: 'Security', title: 'No ISU / WCPISU where user-as-self would work' },
    { id: 'S8', area: 'Security', title: 'No secrets in code; no Base64 basic auth' },
    { id: 'D1', area: 'Data model', title: 'Business objects are related through reference fields' },
    { id: 'D2', area: 'Data model', title: 'No unused business objects' },
    { id: 'E1', area: 'Endpoints', title: 'No hardcoded hosts in pages or data providers' },
    { id: 'E2', area: 'Endpoints', title: 'Data provider values built from apiGatewayEndpoint / site.applicationId' },
    { id: 'E3', area: 'Endpoints', title: 'Every endpoint has failOnStatusCodes for 400 and 403' },
    { id: 'E4', area: 'Endpoints', title: 'No isCollection or bestEffort' },
    { id: 'E5', area: 'Endpoints', title: 'Explicit limit on every app GET' },
    { id: 'E6', area: 'Endpoints', title: 'No large unfiltered lists loaded up front' },
    { id: 'E7', area: 'Endpoints', title: 'No unused endpoints' },
    { id: 'E8', area: 'Endpoints', title: 'No unused data providers; no RaaS' },
    { id: 'E9', area: 'Endpoints', title: 'WQL written as readable text, encoded once' },
    { id: 'C1', area: 'Scripting', title: 'Use + instead of string:join / string:concat' },
    { id: 'C2', area: 'Scripting', title: 'Boolean attributes use true/false, not strings' },
    { id: 'C3', area: 'Scripting', title: 'No unnecessary empty arrays' },
    { id: 'C4', area: 'Scripting', title: 'Null handling on pod and grid column values' },
    { id: 'C5', area: 'Scripting', title: 'No unused functions' },
    { id: 'C6', area: 'Scripting', title: 'No pageVariables or session variables' },
    { id: 'C7', area: 'Scripting', title: 'No constant hidden flags' },
    { id: 'U1', area: 'Widgets & UI', title: 'Widget ids present and unique' },
    { id: 'U2', area: 'Widgets & UI', title: 'No invalid properties on tags' },
    { id: 'U3', area: 'Widgets & UI', title: 'No commented-out _ properties' },
    { id: 'U4', area: 'Widgets & UI', title: 'Grid paging not combined with sortable/filterable columns' },
    { id: 'U5', area: 'Widgets & UI', title: 'Cards are used and not redundant' },
    { id: 'U6', area: 'Widgets & UI', title: 'Follows Workday UI standards (UI/UX video review)', manual: true },
    { id: 'A1', area: 'Attributes & docs', title: 'Every app attribute is used' },
    { id: 'A2', area: 'Attributes & docs', title: 'Deployment Guide covers every setting and matches the code', manual: true },
    { id: 'A3', area: 'Attributes & docs', title: 'User Guide describes the current build', manual: true },
    { id: 'P0', area: 'Package', title: 'Every file in the export parses', internal: true }
  ];

  /* The Build Checklist half of the Workday sheet (wording from the review sheet). */
  var BUILD_CHECKLIST = [
    ['Partner Offering Directory Submission', 'App Name', 'Required', 'The App name as it should appear on Partner Center', ''],
    ['Partner Offering Directory Submission', 'App Description', 'Required', 'A summary description of the App as it should appear internally in the Partner Offering Directory', ''],
    ['Partner Offering Directory Submission', 'Partner Entity Name', 'Required', 'Your enrolled entity name - this should be consistent across applications', ''],
    ['Partner Offering Directory Submission', 'App Lead', 'Required', 'Name and email address of the App lead', ''],
    ['Partner Offering Directory Submission', 'Producer Developer Support Contact', 'Required', 'Name and email address of a single producer developer support contact. This is where any support requests we receive will be routed. We recommend a centralised mailbox for support requests e.g. bowsupport@partnername.com. Only one contact can be named.', ''],
    ['Partner Offering Directory Submission', 'Related Workday Products', 'Required', 'Please select the Workday Product SKUs that your application relates to', ''],
    ['Partner Offering Directory Submission', 'Dependent Workday Services', 'Required', 'Please select the Workday Product SKUs that your application is dependent upon to function', ''],
    ['Partner Offering Directory Submission', 'App Ref ID', 'Action', 'The App Ref ID taken from developer.workday.com (devsite). Workday obtains your latest code from the devsite for a line-by-line build review plus automated tooling that uses LLMs. By providing your App Ref ID, you agree to that usage.', ''],
    ['Preparation for Build Review', 'In-App Validations Cleared', 'Required', 'Ensure all in-application validations are cleared down as these will feature as the first check of the build review', ''],
    ['Test Deployment', 'Test Deployment Executed', 'Required', 'Please follow the deployment guide and implement your application in your second provided Built on Workday tenant. This exercise will highlight any gaps in your documentation, prevent questions being highlighted / issues being raised by your first implementing customers & surface any implementation bugs that may have been missed', ''],
    ['Implementation', 'Implementation Tenant Requirement?', 'Required', 'Is an implementation tenant required to install + test the app in the customer environment? i.e. Will the install take longer than 3-5 days in Sandbox?', ''],
    ['Preparation for Build Review', 'Data Flow Diagram & Reference Architecture', 'Required', 'Please provide a data flow diagram & reference architecture for your application to assist with the build review', ''],
    ['Guides', 'User Guide', 'Required', 'An end-user guide on how to use the app itself. Should be from the perspective of the day-to-day, not necessarily the admin persona or setup instructions.', 'User Guide Template'],
    ['Guides', 'Deployment Documentation', 'Required', 'A guide on any in-tenant config and in-app config needed to get the app up and running (security domains, app attributes, what is needed, etc.). The end user should be able to pick this guide up and know how to get the app and all supporting components in a working state.', 'Deployment Guide Template'],
    ['GTM Asset', 'Solution Card completed for the App', 'Required', 'Please complete the solution card template and upload the completed version to this line. PLEASE NOTE: .PPTX format is required for this file', ''],
    ['UI / UX', 'User Interface / User Experience', 'Required', 'Please provide a recorded technical walkthrough (2\u20133 minutes) demonstrating the end-to-end flow of your app, UI navigation standards, and successful execution of core app logic. UI Review: look & feel, colors, spacing, icons, widgets. UX Review: logic & flow, intuitive navigation.', '']
  ];

  /* Property/tag pairs the Workday reviewer's validator rejected on real submissions. */
  var INVALID_PROPS = [
    { types: ['text'], prop: 'multiLine' },
    { types: ['richText'], prop: 'multiLine' },
    { types: ['text', 'richText', 'instanceList'], prop: 'labelPosition' },
    { types: ['section'], prop: 'justify' },
    { types: ['button', 'pageActionButton'], prop: 'enabled' },
    { types: ['outboundVariable'], prop: 'failOnStatusCodes' }
  ];

  var WIDGETS_NEEDING_ID = ['text', 'number', 'date', 'checkBox', 'dropdown', 'button', 'grid', 'fieldSet', 'section', 'richText', 'hidden', 'instanceList', 'readOnlyText', 'pageActionButton', 'panelList', 'loop', 'title'];

  /* ------------------------------ the audit ------------------------------ */
  function runAudit(rawFiles, options) {
    options = options || {};
    var findings = [];
    var details = [];
    var seq = 0;

    // normalise paths: drop a single shared top-level folder
    var files = rawFiles.filter(function (f) { return f && f.path && !/\/$/.test(f.path); });
    var tops = {};
    files.forEach(function (f) { tops[f.path.split('/')[0]] = 1; });
    var topKeys = Object.keys(tops);
    if (topKeys.length === 1 && files.every(function (f) { return f.path.indexOf('/') > -1; })) {
      files = files.map(function (f) { return { path: f.path.slice(topKeys[0].length + 1), text: f.text }; });
    }
    files = files.filter(function (f) { return TEXT_EXT[extOf(f.path)]; });

    function add(f) {
      f.order = seq++;
      f.details = f.details || [];
      f.details.forEach(function (d) { details.push({ rule: f.rule, type: f.type, component: f.component, comment: f.comment, file: d.file || '', line: d.line || '', snippet: d.snippet || '' }); });
      findings.push(f);
      return f;
    }

    var lineCache = {};
    function lineText(path, line) {
      if (!lineCache[path]) {
        var f = files.find(function (x) { return x.path === path; });
        lineCache[path] = f ? f.text.split('\n') : [];
      }
      var s = (lineCache[path][line - 1] || '').trim();
      return s.length > 180 ? s.slice(0, 177) + '...' : s;
    }
    function det(path, line, snippet) { return { file: baseName(path), line: line, snippet: snippet !== undefined ? snippet : lineText(path, line) }; }
    function mask(v) { v = String(v); return v.slice(0, 2) + new Array(Math.max(3, Math.min(8, v.length - 1))).join('*'); }

    // parse everything that is JSON-ish
    var parsed = {}, parseErrors = [];
    files.forEach(function (f) {
      if (extOf(f.path) === 'script') return;
      var r = parseLenient(f.text);
      parsed[f.path] = r;
      if (r.error) parseErrors.push({ path: f.path, error: r.error });
    });
    parseErrors.forEach(function (pe) {
      add({ rule: 'P0', component: baseName(pe.path), comment: 'File could not be parsed', type: 'Action',
        recommended: 'The file is not valid JSON, so Studio and the reviewer cannot read it: ' + pe.error.message,
        details: [det(pe.path, pe.error.line || 1)] });
    });
    // \' is not a legal JSON escape (Jackson: "Unrecognized character escape ''' (code 39)")
    files.forEach(function (f) {
      var r = parsed[f.path];
      if (r && r.badEscapes.length) {
        add({ rule: 'P0', component: baseName(f.path) + ' - Line: ' + r.badEscapes[0], comment: 'Invalid JSON escape \\\' in ' + plural(r.badEscapes.length, 'place'), type: 'Action',
          recommended: "JSON does not allow \\' \u2014 a single quote never needs escaping. Remove the backslash (or use \\\" where a quote is needed). The app source fails to parse on import otherwise.",
          details: r.badEscapes.map(function (l) { return det(f.path, l); }) });
      }
    });

    function jsonOf(path) { var r = parsed[path]; return r && !r.error ? r.value : null; }
    function ofExt(ext) { return files.filter(function (f) { return extOf(f.path) === ext; }); }

    var manifest = null;
    files.forEach(function (f) { if (baseName(f.path) === 'appManifest.json') manifest = jsonOf(f.path); });
    var amdFile = ofExt('amd')[0], smdFile = ofExt('smd')[0];
    var amd = amdFile ? jsonOf(amdFile.path) : null;
    var appRef = (manifest && manifest.referenceId) || (amd && amd.applicationId) || '';
    function prettyName(s) {
      return String(s).split(/[_\-\s]+/).filter(Boolean).map(function (w) { return cap(w).replace(/iq$/i, 'IQ'); }).join(' ');
    }
    var appName = options.appName || prettyName((manifest && manifest.name) || (appRef ? appRef.replace(/_[a-z0-9]+$/i, '') : 'App'));
    var appToken = (manifest && manifest.name ? manifest.name : appName).toLowerCase().replace(/[^a-z0-9]/g, '');

    var pmds = ofExt('pmd'), pods = ofExt('pod'), cards = ofExt('card'), scripts = ofExt('script');
    var corpus = files.filter(function (f) { return ['pmd', 'pod', 'script', 'amd', 'smd', 'orchestration', 'card'].indexOf(extOf(f.path)) > -1; });
    var corpusText = corpus.map(function (f) { return f.text; }).join('\n');

    var scriptByName = {};
    scripts.forEach(function (s) { scriptByName[baseName(s.path)] = s; });
    var podById = {};
    pods.forEach(function (p) { var j = jsonOf(p.path); if (j && j.podId) podById[j.podId] = p; });

    /* page models */
    var pages = pmds.map(function (f) {
      var j = jsonOf(f.path) || {};
      var includes = (Array.isArray(j.include) ? j.include : []).map(function (n) { return scriptByName[baseName(String(n))]; }).filter(Boolean);
      var podIds = {};
      walk(j.presentation, function (o) { if (!Array.isArray(o) && o.podId) podIds[o.podId] = 1; });
      var usedPods = Object.keys(podIds).map(function (id) { return podById[id]; }).filter(Boolean);
      var endpoints = Array.isArray(j.endPoints) ? j.endPoints.filter(function (e) { return e && e.name; }) : [];
      var withoutEndpoints = {};
      Object.keys(j).forEach(function (k) { if (k !== 'endPoints') withoutEndpoints[k] = j[k]; });
      return { file: f, path: f.path, base: stem(f.path), json: j, includes: includes, pods: usedPods, endpoints: endpoints,
        rootText: JSON.stringify(withoutEndpoints) + '\n' + includes.map(function (s) { return s.text; }).join('\n') + '\n' + usedPods.map(function (p) { return p.text; }).join('\n'),
        pageText: JSON.stringify(j) + '\n' + includes.map(function (s) { return s.text; }).join('\n') };
    });

    /* ===================== SECURITY ===================== */
    var domains = ofExt('securitydomain').map(function (f) { return { file: f, json: jsonOf(f.path) || {} }; });
    domains.forEach(function (d) {
      var miss = [];
      if (d.json.enabledForPageSecurity !== true) miss.push('enabledForPageSecurity');
      if (d.json.enabledForOrchestrationSecurity !== true) miss.push('enabledForOrchestrationSecurity');
      if (miss.length) add({ rule: 'S1', component: baseName(d.file.path), comment: 'Security domain not enabled for ' + miss.join(' / '), type: 'Action',
        recommended: 'Set enabledForPageSecurity and enabledForOrchestrationSecurity to true on every app security domain.', details: [det(d.file.path, 1)] });
    });
    var domainNames = domains.map(function (d) { return d.json.name; }).filter(Boolean);

    pages.forEach(function (p) {
      var sd = p.json.securityDomains;
      if (!Array.isArray(sd) || !sd.length) {
        add({ rule: 'S2', component: baseName(p.path), comment: 'No page security domain defined', type: 'Action',
          recommended: 'Every PMD must declare securityDomains: [...]. Page security is required on all pages, even if it is set to everyone.', details: [det(p.path, 1)] });
      } else if (domainNames.length) {
        sd.forEach(function (name) {
          if (domainNames.indexOf(name) === -1) add({ rule: 'S2', component: baseName(p.path), comment: 'Page references an undefined security domain: ' + name, type: 'Action',
            recommended: 'Add the security domain to the model, or point the page at an existing one.', details: [det(p.path, p.json.__keyLines && p.json.__keyLines.securityDomains || 1)] });
        });
      }
    });

    ofExt('orchestration').forEach(function (f) {
      var j = jsonOf(f.path);
      if (j && (!Array.isArray(j.securityDomains) || !j.securityDomains.length)) {
        add({ rule: 'S3', component: baseName(f.path), comment: 'Orchestration has no security domain', type: 'Action',
          recommended: 'Assign a security domain to every orchestration (securityDomains must not be null).', details: [det(f.path, 1)] });
      }
    });

    var bos = files.filter(function (f) { return extOf(f.path) === 'businessobject' || extOf(f.path) === 'attachment'; }).map(function (f) { return { file: f, json: jsonOf(f.path) || {} }; });
    bos.forEach(function (b) {
      var dsd = b.json.defaultSecurityDomains;
      if (!Array.isArray(dsd) || !dsd.length) {
        add({ rule: 'S4', component: baseName(b.file.path), comment: 'No default security domain', type: 'Action',
          recommended: 'Every business object needs a default security domain.', details: [det(b.file.path, 1)] });
        return;
      }
      var hasTarget = false;
      walk(b.json, function (o) { if (!Array.isArray(o) && o.secureByTarget) hasTarget = true; });
      if (!hasTarget) add({ rule: 'S4', component: baseName(b.file.path), comment: 'No contextual security applied', type: 'Advice',
        recommended: "If no secure by target is defined please confirm no constrained security groups are attached to the security domains securing business object. Constrained security groups do not work on business objects that do not have a defined 'secure by target'.",
        details: [det(b.file.path, b.json.__keyLines && b.json.__keyLines.defaultSecurityDomains || 1)] });
    });

    var boNames = bos.map(function (b) { return (b.json.name || stem(b.file.path)); });
    domains.forEach(function (d) {
      if (d.json.name && boNames.some(function (n) { return n.toLowerCase() === String(d.json.name).toLowerCase(); })) {
        add({ rule: 'S5', component: baseName(d.file.path), comment: 'Security domain name matches a business object name', type: 'Advice',
          recommended: 'A domain used for pages or orchestrations must not share its name with a business object. Rename one of them.', details: [det(d.file.path, 1)] });
      }
    });

    // S6: domains named after the app, and queries that look the domain up by name
    var domainQueries = [];
    corpus.forEach(function (f) {
      var re = /domainName\s*=\s*(?:\\"|"|')([^"'\\]*)/g, m;
      while ((m = re.exec(f.text))) domainQueries.push({ file: f, literal: m[1].trim(), line: lineOfIndex(f.text, m.index) });
    });
    var badQueries = domainQueries.filter(function (q) { return appToken && q.literal.toLowerCase().replace(/[^a-z0-9]/g, '').indexOf(appToken) === -1; });
    if (badQueries.length) {
      var filesHit = {};
      badQueries.forEach(function (q) { filesHit[q.file.path] = 1; });
      var ex = badQueries[0].literal;
      add({ rule: 'S6', component: 'General feedback/Deployment guide', comment: 'Name of domain', type: 'Action',
        recommended: "Your security domain is queried as '" + ex + "' in " + plural(Object.keys(filesHit).length, 'file') + ". Customers may already have a domain with a generic name like this. Recommend adding " + cap(appName) + " to the domain name, e.g. FROM domainSecurityPolicies WHERE domainName=\"" + cap(appName) + " Admin\". This needs updating in the app code queries and in the Deployment Guide.",
        details: badQueries.map(function (q) { return det(q.file.path, q.line); }) });
    }
    var genericDomains = domains.filter(function (d) { return d.json.name && appToken && String(d.json.name).toLowerCase().replace(/[^a-z0-9]/g, '').indexOf(appToken) === -1; });
    if (genericDomains.length && !badQueries.length) {
      add({ rule: 'S6', component: 'General feedback/Deployment guide', comment: 'Name of domain', type: 'Advice',
        recommended: 'Security domains (' + genericDomains.map(function (d) { return d.json.name; }).join(', ') + ') do not carry the app name. A customer may already have a domain with a generic name. Prefer names like "' + cap(appName) + ' Admin" and update queries and the Deployment Guide to match.',
        details: genericDomains.map(function (d) { return det(d.file.path, 1); }) });
    }

    // S7: ISU in the site definition
    if (smdFile) {
      var smd = jsonOf(smdFile.path);
      var auth = smd && smd.siteAuth && smd.siteAuth.authTypes;
      if (Array.isArray(auth)) auth.forEach(function (a) {
        if (a && /ISU/i.test(String(a.scheme))) {
          var ln = (a.__keyLines && a.__keyLines.scheme) || a.__line || 1;
          add({ rule: 'S7', component: baseName(smdFile.path) + ' - Line: ' + ln, comment: 'WCPISU or ISU in use', type: 'Advice',
            recommended: 'Consider reviewing the requirement of third party security via ISU, can the app leverage user as self security or the existing security models within Workday to remove the need for an ISU and associated configuration? If an ISU stays, justify it and document its setup.',
            details: [det(smdFile.path, ln)] });
        }
      });
    }

    // S8: secrets and Base64 basic auth
    corpus.forEach(function (f) {
      var t = f.text, re = /Basic\s+([A-Za-z0-9+\/=]{8,})/g, m, hits = [];
      while ((m = re.exec(t))) hits.push({ line: lineOfIndex(t, m.index), snippet: 'Basic ' + mask(m[1]) });
      if (hits.length) add({ rule: 'S8', component: baseName(f.path) + ' - Line: ' + hits[0].line, comment: 'Possible Base64 basic auth in code', type: 'Action',
        recommended: 'Base64 basic-auth is not supported in Built on Workday and secrets must not live in code. Use SSO / user-as-self or a supported auth scheme.', details: hits.map(function (h) { return det(f.path, h.line, h.snippet); }) });
    });
    files.filter(function (f) { return ['orchestration', 'pmd', 'amd', 'smd', 'pod'].indexOf(extOf(f.path)) > -1; }).forEach(function (f) {
      var t = f.text, re = /\\*"(password|passwd|secret|client_secret|clientSecret|apiKey|api_key|accessToken|authToken)\\*"\s*:\s*\\*"(?!<%)([^"\\]{4,})/gi, m, hits = [];
      while ((m = re.exec(t))) hits.push({ line: lineOfIndex(t, m.index), snippet: m[1] + ' = ' + mask(m[2]) + ' (value hidden)' });
      if (hits.length) add({ rule: 'S8', component: baseName(f.path) + ' - Line: ' + hits[0].line, comment: 'Possible hardcoded secret', type: 'Action',
        recommended: 'No secrets in code or app attributes. Remove the literal value; keep credentials out of the app source (user-as-self where possible, otherwise document how the customer configures it).', details: hits.map(function (h) { return det(f.path, h.line, h.snippet); }) });
    });

    /* ===================== DATA MODEL ===================== */
    var realBos = bos.filter(function (b) { return extOf(b.file.path) === 'businessobject'; });
    if (realBos.length > 1) {
      var related = false;
      realBos.forEach(function (b) {
        (b.json.fields || []).forEach(function (fld) {
          if (fld && /INSTANCE/i.test(String(fld.type)) && fld.target && realBos.some(function (o) { return o !== b && (o.json.name === fld.target); })) related = true;
        });
      });
      if (!related) add({ rule: 'D1', component: 'Business Objects', comment: 'No relationships established', type: 'Action',
        recommended: 'Your business objects are not related to each other \u2014 they are all free-standing. If this is by design, say so in the Partner Comment; it limits reporting on the data. Otherwise add reference (instance) fields between them.',
        details: realBos.map(function (b) { return det(b.file.path, 1); }) });
    }
    bos.forEach(function (b) {
      var coll = b.json.defaultCollection && b.json.defaultCollection.name, nm = b.json.name || stem(b.file.path);
      var used = (coll && countWord(corpusText, coll)) || countWord(corpusText, nm) || (coll && corpusText.indexOf(coll) > -1);
      if (!used) add({ rule: 'D2', component: baseName(b.file.path), comment: 'Possible unused business object', type: 'Advice',
        recommended: 'Nothing in the app reads or writes ' + nm + (coll ? ' (' + coll + ')' : '') + '. Delete test and scaffold objects, or confirm it is used.', details: [det(b.file.path, 1)] });
    });

    /* ===================== ENDPOINTS ===================== */
    // Which instanceList (if any) does this endpoint fill? Follows helper functions that wrap the endpoint.
    function fnBodies(text) {
      var re = /\bvar\s+([A-Za-z_]\w*)\s*=\s*function\b/g, m, marks = [];
      while ((m = re.exec(text))) marks.push({ name: m[1], at: m.index });
      return marks.map(function (mk, i) { return { name: mk.name, body: text.slice(mk.at, i + 1 < marks.length ? marks[i + 1].at : text.length) }; });
    }
    function instanceListFedBy(p, endpointName) {
      var scriptText = (typeof p.json.script === 'string' ? p.json.script : '') + '\n' + p.includes.map(function (s) { return s.text; }).join('\n');
      var bodies = fnBodies(scriptText), feeders = {}, changed = true, guard = 0;
      feeders[endpointName] = 1;
      while (changed && guard++ < 4) {
        changed = false;
        bodies.forEach(function (b) {
          if (!feeders[b.name] && Object.keys(feeders).some(function (k) { return countWord(b.body, k) > 0; })) { feeders[b.name] = 1; changed = true; }
        });
      }
      var names = Object.keys(feeders), hit = '';
      walk(p.json.presentation, function (o) {
        if (hit || Array.isArray(o) || o.type !== 'instanceList') return;
        var s = JSON.stringify(o);
        if (names.some(function (n) { return countWord(s, n) > 0; })) hit = o.id || 'instanceList';
      });
      return hit;
    }
    function largeEndpoint(p, e, what) {
      var il = instanceListFedBy(p, e.name);
      if (il) {
        add({ rule: 'E6', component: baseName(p.path), comment: 'Large endpoint', type: 'Action',
          recommended: 'Endpoint ' + e.name + ' loads ' + what + ' up front to fill the instanceList "' + il + '". The limit may truncate your data set and this is a poorly performing pattern. Recommend using a search endpoint instead (searchEndPoint driven by instanceListQuery, so the list is filled from what the user types).',
          details: [det(p.path, e.__line || 1)] });
      } else {
        add({ rule: 'E6', component: baseName(p.path), comment: 'Large endpoint', type: 'Advice',
          recommended: 'Endpoint ' + e.name + ' is a big call: it reads ' + what + ' with no WHERE condition, and the limit may truncate your data set. That can be fine if the page genuinely needs the full set, but look for an alternative where you can: filter in the query (WHERE), page the results, or select only the fields the page uses.',
          details: [det(p.path, e.__line || 1)] });
      }
    }

    var providers = (amd && Array.isArray(amd.dataProviders)) ? amd.dataProviders : [];
    var hostRe = /https?:\/\/[^\s"'<>)]+/;
    providers.forEach(function (p) {
      var v = String(p.value || ''), ln = (p.__line || 1);
      if (/(^|[^A-Za-z])api(\.[a-z]+)?\.(wcp\.)?workday\.com|workday\.com\/(wql|common|apps|staffing|connect)/i.test(v) || (appRef && v.indexOf(appRef) > -1)) {
        add({ rule: 'E2', component: baseName(amdFile.path) + ' - Provider: ' + p.key, comment: 'Data provider writes out the gateway host or app id', type: 'Action',
          recommended: "Build data provider values from apiGatewayEndpoint and site.applicationId \u2014 never write the gateway host or the app ID out.", details: [det(amdFile.path, ln)] });
      } else if (hostRe.test(v) && v.indexOf('apiGatewayEndpoint') === -1) {
        add({ rule: 'E1', component: baseName(amdFile.path) + ' - Provider: ' + p.key, comment: 'Data provider uses a hardcoded host', type: 'Advice',
          recommended: 'Provider "' + p.key + '" points at a fixed external host (' + (v.match(hostRe) || [''])[0] + '). Confirm it is an external service the app genuinely needs, and document the dependency in the Deployment Guide.', details: [det(amdFile.path, ln)] });
      }
    });
    pages.concat(pods.map(function (f) { return { path: f.path, file: f, base: stem(f.path), json: jsonOf(f.path) || {} }; })).forEach(function (p) {
      var t = p.file.text, hits = [], re = /https?:\/\/[A-Za-z0-9.\-]+[^\s"'<>)]*/g, m;
      while ((m = re.exec(t))) hits.push({ line: lineOfIndex(t, m.index), url: m[0] });
      if (hits.length) add({ rule: 'E1', component: baseName(p.path) + ' - Line: ' + hits[0].line, comment: 'Hardcoded host in ' + plural(hits.length, 'URL'), type: 'Action',
        recommended: 'Every endpoint needs a baseUrlType backed by a data provider in the AMD. No hardcoded hosts, including in link URLs.', details: hits.map(function (h) { return det(p.path, h.line); }) });
    });
    // E8: unused data providers, RaaS
    providers.forEach(function (p) {
      var usedAsBase = new RegExp('["\']' + esc(p.key) + '["\']').test(corpus.filter(function (f) { return extOf(f.path) !== 'amd'; }).map(function (f) { return f.text; }).join('\n'));
      if (!usedAsBase) add({ rule: 'E8', component: baseName(amdFile.path) + ' - Provider: ' + p.key, comment: 'Data provider not in use', type: 'Action',
        recommended: 'No endpoint uses "' + p.key + '" as its baseUrlType. Remove data providers that nothing uses.', details: [det(amdFile.path, p.__line || 1)] });
      if (/customreport|raas/i.test(String(p.value || '') + String(p.key))) add({ rule: 'E8', component: baseName(amdFile.path) + ' - Provider: ' + p.key, comment: 'Report-as-a-Service (RaaS) data provider', type: 'Action',
        recommended: 'No Report-as-a-Service (RaaS). Replace with WQL or the app\'s own business objects.', details: [det(amdFile.path, p.__line || 1)] });
    });

    pages.forEach(function (p) {
      var pageName = baseName(p.path);
      p.endpoints.forEach(function (e) {
        var codes = (Array.isArray(e.failOnStatusCodes) ? e.failOnStatusCodes : []).map(function (c) { return c && c.code; });
        if (codes.indexOf(400) === -1 || codes.indexOf(403) === -1) {
          add({ rule: 'E3', component: pageName + ' - Endpoint: ' + e.name, comment: 'Missing failOnStatusCodes', type: 'Action',
            recommended: 'Every endpoint needs failOnStatusCodes for 400 and 403.', details: [det(p.path, e.__line || 1)] });
        }
        var urlStr = JSON.stringify(e.url || '') + JSON.stringify(e.wqlQuery || '');
        if (e.baseUrlType === 'app' && !/limit/i.test(urlStr)) {
          add({ rule: 'E5', component: pageName + ' - Endpoint: ' + e.name, comment: 'Endpoint Limits', type: 'Advice',
            recommended: 'For this endpoint, you have not set a limit so the maximum number of records returned via this method is 20. If this could be exceeded in a customer environment, please adjust',
            details: [det(p.path, e.__keyLines && e.__keyLines.url || e.__line || 1)] });
        }
        var q = (e.wqlQuery && e.wqlQuery.query) || '';
        if (!q && /query=/i.test(String(e.url || ''))) q = String(e.url);
        if (e.baseUrlType === 'workday-wql' || /wql/i.test(String(e.baseUrlType))) {
          var fromDs = /\bFROM\s+(all[A-Za-z]*|workers[A-Za-z]*)\b/i.exec(q);
          if (fromDs && !/\bWHERE\b/i.test(q)) largeEndpoint(p, e, 'every record from ' + fromDs[1]);
          if (/data\?query=[^"]*%(20|27|2C|3D|22)/i.test(String(e.url || ''))) {
            add({ rule: 'E9', component: pageName + ' - Endpoint: ' + e.name, comment: 'WQL appears to be pre-encoded', type: 'Advice',
              recommended: 'Write WQL as readable text and encode it once with urlEncode() when the url is built.', details: [det(p.path, e.__line || 1)] });
          }
        }
        if (/^\/?workers\/?(\?|$)/.test(String(e.url || '')) && !/search=|filter|query/i.test(String(e.url))) {
          largeEndpoint(p, e, 'all workers');
        }
      });
    });
    corpus.forEach(function (f) {
      var t = f.text, re = /"(isCollection|bestEffort)"/g, m, hits = [];
      while ((m = re.exec(t))) hits.push(lineOfIndex(t, m.index));
      if (hits.length) add({ rule: 'E4', component: baseName(f.path) + ' - Line: ' + hits[0], comment: 'isCollection / bestEffort in use', type: 'Action',
        recommended: 'Remove isCollection and bestEffort from endpoints.', details: hits.map(function (l) { return det(f.path, l); }) });
    });

    // E7: unused endpoints, including those only used by other unused endpoints
    pages.forEach(function (p) {
      if (!p.endpoints.length) return;
      var names = p.endpoints.map(function (e) { return e.name; });
      var blocks = {};
      p.endpoints.forEach(function (e) { blocks[e.name] = JSON.stringify(e); });
      var direct = {};
      names.forEach(function (nm) { if (countWord(p.rootText, nm) > 0) direct[nm] = 1; });
      // live = reachable from the page body / scripts / pods, following endpoint-to-endpoint references
      var live = {}, queue = Object.keys(direct);
      queue.forEach(function (nm) { live[nm] = 1; });
      while (queue.length) {
        var cur = queue.pop();
        names.forEach(function (nm) { if (!live[nm] && nm !== cur && countWord(blocks[cur], nm) > 0) { live[nm] = 1; queue.push(nm); } });
      }
      var dead = names.filter(function (nm) { return !live[nm]; });
      if (!dead.length) return;
      // a dead endpoint that only another dead endpoint uses is reported as "thereby" removable
      var referenced = {};
      dead.forEach(function (a) { dead.forEach(function (b) { if (a !== b && countWord(blocks[b], a) > 0) referenced[a] = 1; }); });
      var roots = dead.filter(function (nm) { return !referenced[nm]; });
      if (!roots.length) roots = [dead[0]];
      roots.forEach(function (r) {
        var seen = {}, stack = [r], deps = [];
        seen[r] = 1;
        while (stack.length) {
          var c2 = stack.pop();
          dead.forEach(function (nm) { if (!seen[nm] && countWord(blocks[c2], nm) > 0) { seen[nm] = 1; deps.push(nm); stack.push(nm); } });
        }
        var e = p.endpoints.find(function (x) { return x.name === r; });
        add({ rule: 'E7', component: baseName(p.path), comment: 'Possible Unused Endpoint', type: 'Action',
          recommended: 'Is the endpoint ' + r + ' in use? If not, please remove.' + (deps.length ? ' (and thereby ' + deps.join(', ') + ')' : ''), details: [det(p.path, e.__line || 1)] });
      });
    });

    /* ===================== SCRIPTING ===================== */
    var hits;
    // C1
    hits = [];
    corpus.forEach(function (f) { var re = /string:(join|concat)/g, m; while ((m = re.exec(f.text))) hits.push({ f: f, line: lineOfIndex(f.text, m.index) }); });
    if (hits.length) add({ rule: 'C1', component: 'General Feedback', comment: '"string:join" or "string:concat" scripting method used ' + hits.length + ' time(s)', type: 'Advice',
      recommended: 'The "+" operator is more intuitive, and has fewer limitations than the string:join and string:concat PMD Functions (e.g. "string" + "string").',
      details: hits.map(function (h) { return det(h.f.path, h.line); }) });
    // C2
    hits = [];
    files.filter(function (f) { return extOf(f.path) !== 'script' && extOf(f.path) !== 'attributes'; }).forEach(function (f) {
      var re = /"([A-Za-z_]+)"\s*:\s*"(true|false)"/g, m;
      while ((m = re.exec(f.text))) hits.push({ f: f, line: lineOfIndex(f.text, m.index) });
    });
    if (hits.length) add({ rule: 'C2', component: 'Scripting', comment: 'String booleans in use ' + hits.length + ' time(s)', type: 'Advice',
      recommended: 'Use the boolean value for boolean attributes, do not use the string representation of the boolean value (i.e. use true, not "true")',
      details: hits.map(function (h) { return det(h.f.path, h.line); }) });
    // C3: [] inside PMD expressions and script files
    var emptyArr = [], emptyTotal = 0;
    pods.concat(pmds).forEach(function (f) {
      var j = jsonOf(f.path); if (!j) return;
      var c = 0;
      walkStrings(j, function (s) { if (s.indexOf('<%') > -1) { var m = s.match(/\[\s*\]/g); if (m) c += m.length; } });
      if (c) { emptyTotal += c; emptyArr.push({ f: f, n: c }); }
    });
    scripts.forEach(function (f) { var m = f.text.match(/\[\s*\]/g); if (m) { emptyTotal += m.length; emptyArr.push({ f: f, n: m.length }); } });
    if (emptyTotal) add({ rule: 'C3', component: 'Scripting', comment: 'Empty array referenced in file ' + emptyTotal + ' time(s)', type: 'Advice',
      recommended: 'An empty array [] has been leveraged, is there a reason for this empty instance being referenced? Use list:emptyList() for lists that are filled in; null-safe fallbacks such as data ?: [] are fine but be ready to explain each one.',
      details: emptyArr.sort(function (a, b) { return b.n - a.n; }).map(function (e) { var ix = e.f.text.search(/\[\s*\]/); return { file: baseName(e.f.path), line: ix > -1 ? lineOfIndex(e.f.text, ix) : '', snippet: e.n + ' occurrence(s) in this file' }; }) });
    // C6: pageVariables / session variables
    hits = [];
    corpus.forEach(function (f) { var re = /pageVariables\./g, m; while ((m = re.exec(f.text))) hits.push({ f: f, line: lineOfIndex(f.text, m.index) }); });
    if (hits.length) add({ rule: 'C6', component: 'pageVariables', comment: hits.length + ' instances of pageVariables found (pageVariables.)', type: 'Advice',
      recommended: 'Excessive use of pageVariables may impact page performance. Replace with flow variables or plain values.',
      details: hits.map(function (h) { return det(h.f.path, h.line); }) });
    pages.concat(pods.map(function (f) { return { path: f.path, file: f, json: jsonOf(f.path) || {} }; })).forEach(function (p) {
      var sess = [];
      walk(p.json, function (o) {
        if (!Array.isArray(o) && String(o.variableScope).toLowerCase() === 'session') {
          sess.push({ line: (o.__keyLines && o.__keyLines.variableScope) || o.__line, obj: o });
        }
      });
      var t = p.file.text, m, re = /pmdSessionVariables\./g;
      while ((m = re.exec(t))) sess.push({ line: lineOfIndex(t, m.index) });
      if (sess.length) {
        add({ rule: 'C6', component: baseName(p.path) + ' - Line: ' + sess[0].line, comment: 'Session variable referenced in file', type: 'Action',
          recommended: 'Remove and replace with flow variables. Session variables persist for the duration of the user session and consume memory even after the flow has ended.',
          details: sess.map(function (s) { return det(p.path, s.line); }) });
      }
    });
    // C7: hidden flags set to a constant false
    pages.forEach(function (p) {
      var hit = [];
      walk(p.json.presentation, function (o) {
        if (!Array.isArray(o) && o.type === 'hidden' && (o.value === false || o.value === 'false' || o.value === '<% false %>')) hit.push(o.__line);
      });
      if (hit.length) add({ rule: 'C7', component: baseName(p.path), comment: 'Deletion pattern', type: 'Advice',
        recommended: "You don't need to set a hidden flag to false like this - where are you passing the params or changing this value? It appears to be immutable",
        details: hit.map(function (l) { return det(p.path, l); }) });
    });
    // C4: null handling on pod / grid column values
    function bareChain(v) { return typeof v === 'string' && /^<%\s*[A-Za-z_]\w*(\.\w+)+\s*%>$/.test(v.trim()); }
    pods.concat(pmds).forEach(function (f) {
      var j = jsonOf(f.path); if (!j) return;
      var bad = [];
      walk(j, function (o) {
        if (!Array.isArray(o) && o.type === 'column' && o.cellTemplate && typeof o.cellTemplate === 'object') {
          var ct = o.cellTemplate;
          ['value', 'label'].forEach(function (k) { if (bareChain(ct[k])) bad.push(ct.__keyLines && ct.__keyLines[k] || ct.__line); });
        }
      });
      if (bad.length) add({ rule: 'C4', component: baseName(f.path), comment: 'Missing null handling', type: 'Action',
        recommended: "Add null handling to your column values (i.e. value ?? '' or !empty value ? value : '')", details: bad.map(function (l) { return det(f.path, l); }) });
    });
    // C5: unused functions
    function fnNames(text) { var out = [], re = /\bvar\s+([A-Za-z_]\w*)\s*=\s*function\b/g, m; while ((m = re.exec(text))) out.push(m[1]); return out; }
    pages.forEach(function (p) {
      var script = typeof p.json.script === 'string' ? p.json.script : '';
      var podText = p.pods.map(function (x) { return x.text; }).join('\n');
      fnNames(script).forEach(function (fn) {
        var refs = countWord(p.pageText, fn) - 1;
        if (refs > 0) return;
        var inPods = countWord(podText, fn);
        var ix = script.indexOf('var ' + fn), pageIx = p.file.text.search(new RegExp('var\\s+' + esc(fn) + '\\s*=\\s*function'));
        var ln = pageIx > -1 ? lineOfIndex(p.file.text, pageIx) : 1;
        if (inPods > 0) {
          add({ rule: 'C5', component: baseName(p.path), comment: "Function '" + fn + "' defined in script attribute but only used inside a pod", type: 'Advice',
            recommended: "Function '" + fn + "' is only called from a pod (" + p.pods.map(function (x) { return baseName(x.path); }).join(', ') + "). The review tooling does not read pods and flags this as unused \u2014 answer it in the Partner Comment, or move the logic.", details: [det(p.path, ln)] });
        } else {
          add({ rule: 'C5', component: baseName(p.path), comment: "Function '" + fn + "' defined in script attribute but not used elsewhere on the page", type: 'Action',
            recommended: 'Remove unused/dead code, or reference the function where it is needed.', details: [det(p.path, ln)] });
        }
      });
    });
    scripts.forEach(function (s) {
      var includers = pages.filter(function (p) { return p.includes.indexOf(s) > -1; });
      var names = fnNames(s.text);
      if (!names.length) return;
      if (!includers.length) {
        add({ rule: 'C5', component: baseName(s.path), comment: 'Script file is not included by any page', type: 'Action',
          recommended: 'Remove the script, or include it from the page that needs it.', details: [det(s.path, 1)] });
        return;
      }
      var allText = includers.map(function (p) { return p.pageText + '\n' + p.pods.map(function (x) { return x.text; }).join('\n'); }).join('\n') + '\n' + scripts.filter(function (x) { return x !== s; }).map(function (x) { return x.text; }).join('\n');
      names.forEach(function (fn) {
        var inOwn = countWord(s.text, fn) - 1 - (new RegExp('"' + esc(fn) + '"\\s*:\\s*' + esc(fn) + '\\b').test(s.text) ? 1 : 0);
        var outside = countWord(allText, fn);
        if (inOwn <= 0 && outside <= 0) {
          var ix = s.text.search(new RegExp('var\\s+' + esc(fn) + '\\s*=\\s*function'));
          add({ rule: 'C5', component: baseName(s.path), comment: "Function '" + fn + "' defined in script file but not used", type: 'Action',
            recommended: 'Remove unused/dead code, or reference the function where it is needed.', details: [det(s.path, ix > -1 ? lineOfIndex(s.text, ix) : 1)] });
        }
      });
    });

    /* ===================== WIDGETS & UI ===================== */
    pages.concat(pods.map(function (f) { return { path: f.path, file: f, base: stem(f.path), json: jsonOf(f.path) || {}, isPod: true }; })).forEach(function (p) {
      var root = p.isPod ? p.json.seed : p.json.presentation;
      var seen = {}, pageName = stem(p.path);
      // U2 and U4 look at the whole file (outboundData holds the session-variable blocks)
      walk(p.json, function (o) {
        if (Array.isArray(o)) return;
        var type = typeof o.type === 'string' ? o.type : null;
        INVALID_PROPS.forEach(function (ip) {
          if (ip.types.indexOf(type) > -1 && Object.prototype.hasOwnProperty.call(o, ip.prop)) {
            var ln = (o.__keyLines && o.__keyLines[ip.prop]) || o.__line;
            var tagId = ip.types[0] === 'outboundVariable' ? (o.name || type) : (o.id || o.name || type);
            add({ rule: 'U2', component: pageName + ': Line ' + o.__line, comment: 'Validation item', type: 'Advice',
              recommended: 'You defined an invalid property in tag ' + tagId + ': ' + ip.prop + '. Remove it or prefix it with an underscore.', details: [det(p.path, ln)] });
          }
        });
        if (type === 'grid' && (o.pagingInfo || o.autoPaging === true || o.autoPaging === 'true')) {
          var sortable = Array.isArray(o.columns) && o.columns.some(function (c) { return c && (c.sortableAndFilterable === true || c.sortableAndFilterable === 'true'); });
          if (sortable) add({ rule: 'U4', component: pageName + ': Line ' + o.__line, comment: 'Grid uses paging with sortable/filterable columns', type: 'Advice',
            recommended: 'A grid cannot use paging (pagingInfo or autoPaging) and also have sortableAndFilterable columns. Remove one of them.', details: [det(p.path, o.__line)] });
        }
      });
      walk(root, function (o) {
        if (Array.isArray(o)) return;
        var type = typeof o.type === 'string' ? o.type : null;
        if (type && typeof o.id === 'string') {
          var id = o.id;
          if (seen[id]) {
            add({ rule: 'U1', component: pageName + ': Line ' + ((o.__keyLines && o.__keyLines.id) || o.__line), comment: 'Validation item', type: 'Advice',
              recommended: 'The id ' + id + ' used for ' + tagName(type) + ' has already been declared. Choose a unique id.', details: [det(p.path, (o.__keyLines && o.__keyLines.id) || o.__line)] });
          } else seen[id] = 1;
        } else if (type && WIDGETS_NEEDING_ID.indexOf(type) > -1 && !('id' in o) && !p.isPod) {
          add({ rule: 'U1', component: pageName + ': Line ' + o.__line, comment: 'Validation item', type: 'Advice',
            recommended: 'The ' + tagName(type) + ' has no id. Give every widget an id.', details: [det(p.path, o.__line)] });
        }
      });
    });
    // U3: commented-out _ properties
    files.filter(function (f) { return ['pmd', 'pod', 'amd', 'card', 'businessobject', 'attachment'].indexOf(extOf(f.path)) > -1; }).forEach(function (f) {
      var j = jsonOf(f.path); if (!j) return;
      var keys = [];
      walk(j, function (o) { if (!Array.isArray(o)) Object.keys(o).forEach(function (k) { if (k.charAt(0) === '_') keys.push({ k: k, line: (o.__keyLines && o.__keyLines[k]) || o.__line }); }); });
      if (keys.length) add({ rule: 'U3', component: baseName(f.path) + ' - Line: ' + keys[0].line, comment: plural(keys.length, 'commented-out property') + ' (keys starting with _)', type: 'Advice',
        recommended: 'Do not leave commented-out _ values in the files. They add size and noise.', details: keys.map(function (k) { return det(f.path, k.line); }) });
    });
    // U5: cards
    var cardInfo = cards.map(function (f) { return { file: f, json: jsonOf(f.path) || {} }; });
    cardInfo.forEach(function (c) {
      var id = c.json.id || stem(c.file.path);
      var pat = new RegExp('["\']' + esc(id) + '["\']');
      var used = corpus.some(function (f) { return extOf(f.path) !== 'card' && pat.test(f.text); });
      if (!used) add({ rule: 'U5', component: baseName(c.file.path), comment: 'Card not in use', type: 'Action', recommended: 'Card not in use, can remove', details: [det(c.file.path, 1)] });
    });
    var groups = {};
    cardInfo.forEach(function (c) {
      var key = JSON.stringify(c.json.parameters || []) + '|' + ((c.json.body && c.json.body.type) || '');
      (groups[key] = groups[key] || []).push(c);
    });
    Object.keys(groups).forEach(function (k) {
      var g = groups[k];
      if (g.length >= 3) add({ rule: 'U5', component: 'Cards', comment: 'Redundant cards', type: 'Advice',
        recommended: 'Several of your cards are identical with different data params passed (' + g.map(function (c) { return stem(c.file.path); }).join(', ') + '), could use a single or maybe two parameterised cards rather than ' + g.length + '.',
        details: g.map(function (c) { return det(c.file.path, 1); }) });
    });

    /* ===================== ATTRIBUTES ===================== */
    ofExt('attributes').forEach(function (f) {
      var list = jsonOf(f.path);
      if (!Array.isArray(list)) return;
      list.forEach(function (a) {
        if (!a || !a.name) return;
        var used = new RegExp('attrstore\\s*(\\.|\\[\\s*["\'])' + esc(a.name) + '(?![A-Za-z0-9_])').test(corpusText) || (a.alias && a.alias !== a.name && new RegExp('attrstore\\s*(\\.|\\[\\s*["\'])' + esc(a.alias) + '(?![A-Za-z0-9_])').test(corpusText));
        if (!used) {
          var extra = '';
          if (/secret|password|passwd/i.test(a.name)) extra = ', against best practice to store secrets and passwords anyways';
          else if (/base64|basicauth/i.test(a.name)) extra = '. Base64 is not supported in BoW.';
          add({ rule: 'A1', component: 'Attributes', comment: 'Not in use', type: 'Action',
            recommended: a.name + ' not in use. Remove from codeline as well as deployment guide' + extra, details: [det(f.path, a.__line || 1)] });
        }
      });
    });

    /* ===================== assemble ===================== */
    var areaOrder = ['Security', 'Data model', 'Endpoints', 'Scripting', 'Widgets & UI', 'Attributes & docs', 'Package'];
    var ruleArea = {};
    RULES.forEach(function (r) { ruleArea[r.id] = r.area; });
    findings.sort(function (a, b) {
      var d = areaOrder.indexOf(ruleArea[a.rule]) - areaOrder.indexOf(ruleArea[b.rule]);
      return d || a.order - b.order;
    });

    var counts = { Action: 0, Advice: 0 }, byRule = {};
    findings.forEach(function (f) { counts[f.type]++; byRule[f.rule] = byRule[f.rule] || { Action: 0, Advice: 0 }; byRule[f.rule][f.type]++; });
    var typeCounts = {};
    files.forEach(function (f) { var e = extOf(f.path); typeCounts[e] = (typeCounts[e] || 0) + 1; });

    var build = BUILD_CHECKLIST.map(function (r) {
      var comment = '';
      if (r[1] === 'App Name') comment = cap(appName);
      if (r[1] === 'App Ref ID') comment = appRef;
      return { component: r[0], review: r[1], type: r[2], recommended: r[3], link: r[4], partnerComment: comment };
    });

    return {
      app: { name: cap(appName), referenceId: appRef, hasManifest: !!manifest },
      findings: findings,
      details: details,
      build: build,
      rules: RULES,
      byRule: byRule,
      counts: counts,
      fileCount: files.length,
      typeCounts: typeCounts,
      parseErrors: parseErrors.map(function (p) { return { path: p.path, message: p.error.message }; }),
      looksLikeExport: pmds.length > 0 || !!manifest
    };
  }

  return { runAudit: runAudit, parseLenient: parseLenient, RULES: RULES, BUILD_CHECKLIST: BUILD_CHECKLIST, TEXT_EXT: TEXT_EXT };
});
