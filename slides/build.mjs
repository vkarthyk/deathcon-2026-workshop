/** Build the editable 45-minute workshop deck with the bundled Artifact Tool. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
const root = path.resolve(import.meta.dirname, '..');
const runtime = process.env.RUNTIME_NODE_MODULES || path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules');
process.env.RUNTIME_NODE_MODULES = runtime;
const skill = process.env.PRESENTATION_SKILL_DIR || path.join(os.homedir(), '.codex/plugins/cache/openai-primary-runtime/presentations/26.1025.11240/skills/presentations');
const {Presentation, PresentationFile} = await import(pathToFileURL(path.join(runtime,'@oai/artifact-tool/dist/artifact_tool.mjs')));
const {finalizePresentation, resolvePresentationFont} = await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const build = path.join(root,'artifacts/presentation-build');
await fs.mkdir(build,{recursive:true});
const out = path.join(root,'slides/one-schema-to-rule-them-all.pptx');
const FONT = resolvePresentationFont({fontFamily:'Arial'});
const CODE = 'Menlo';
const C = {bg:'#101A25',fg:'#F7F5EF',muted:'#B6C4CF',cyan:'#69DFD4',amber:'#FFD28B',line:'#304657'};
const p = Presentation.create({slideSize:{width:1280,height:720}});
const article='https://cloudnativedetection.substack.com/p/multi-cloud-detection-at-scale-a';
const notes=[];
function text(s,value,x,y,w,h,size=28,color=C.fg,bold=false,font=FONT,name='body') {
 const shape=s.shapes.add({name,geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
 shape.text=value;
 shape.text.style={typeface:font,fontSize:size,color,bold,verticalAlignment:'top',alignment:'left',wrap:true};
 shape.text.insets=0;
 return shape;
}
function slide(title,time,note){
 const s=p.slides.add();s.background.fill=C.bg;
 text(s,title,64,58,1152,116,46,C.fg,true,FONT,'slide-title');
 text(s,time,64,662,1060,28,18,C.muted,false,FONT,'session-timing');
 text(s,String(p.slides.items.length).padStart(2,'0'),1160,662,56,28,18,C.muted,false,FONT,'page-number');
 s.speakerNotes.text=note;
 notes.push({slide:p.slides.items.length,title,timing:time,notes:note});
 return s;
}
function table(s,values,x,y,width,height,widths,fontSize=26){
 const t=s.tables.add({rows:values.length,columns:values[0].length,left:x,top:y,width,height,columnWidths:widths,values});
 t.borders.assign({fill:C.line,width:1,style:'solid'});
 for(let r=0;r<values.length;r++)for(let c=0;c<values[0].length;c++){
  const cell=t.getCell(r,c);
  cell.fill=r===0?'#18353C':C.bg;
  cell.text.style={typeface:FONT,fontSize,color:r===0?C.cyan:C.fg,bold:r===0,verticalAlignment:'middle'};
 }
 return t;
}

// 1. Minimal cover and workshop promise.
{
 const s=p.slides.add();s.background.fill=C.bg;
 text(s,'One Schema\nto Rule Them All',64,137,1140,210,76,C.fg,true,FONT,'slide-title');
 text(s,'Multi-cloud detection engineering',68,386,1120,48,34,C.cyan);
 text(s,'EKS, GKE and AKS',68,452,1120,44,28,C.muted);
 text(s,'DEATHCon 2026    Ved K    45-minute workshop',68,636,1120,32,22,C.muted);
 const note=`00:00–01:00. Introduce the goal: map one provider, compare the other two, run a shared rule across three clouds, and explain an alert using source evidence. The sequence is a successful cluster-admin grant followed by successful cluster-wide secret listing by the granted User within 15 minutes on the same asset. Matching behavior warrants investigation.\n\nBEFORE THE SESSION: Ask students to run setup.sh or setup.ps1 and open notebook 00 before the workshop. The existing notebooks are a longer core path. For this 45-minute delivery, pick EKS as the common hands-on provider and distribute the GKE and AKS example queries and completed mapping dictionaries from solutions/binding_exercise/ before class. Do not require students to solve all three provider mappings live. Keep collapsed hints available. Prepare an alert and source evidence in case a student falls behind.\n\nPACING: Teaching 00–06 and 23–25. Hands-on 06–23 and 25–38. Discussion 38–42. Close 42–45. This includes 30 minutes of hands-on work.\n\nSources: WORKSHOP.md; README.md; detection/privilege_to_secrets.sql.`;
 s.speakerNotes.text=note;notes.push({slide:1,title:'One Schema to Rule Them All',timing:'00–01 min',notes:note});
}
// 2. Motivation, drawn from the multi-cloud detection article.
{
 const s=slide('Why this workshop: the problem is the data','01–03 min',`Open with the article's thesis: "The problem isn't your detection rules. It's your data." Most large organizations now run workloads on more than one cloud. The article cites Gartner 2024 research putting this at 92% of large enterprises. Each provider records the same behavior with different field names, types and nesting. The article calls this fragmentation a "hidden tax."\n\nWithout normalization, every detection is rewritten, tested and maintained per provider: N detections across M clouds become N×M rules. Rules hard-code raw API names such as eventName or methodName, so a provider format change silently breaks them. The article describes this as "technical debt masquerading as security engineering."\n\nThe proposed fix: keep immutable raw logs for forensics and replay, transform them once into a stable normalized schema, and write detections against shared semantic fields. N×M rules become N detections plus M source adapters. "If your detection logic is complex, your schema design is wrong" — complexity belongs in the transformation, which runs once, not the detection, which runs constantly.\n\nCaveat for the room: the article's speed-up figures (for example, provider onboarding from months to days) are the author's estimates without stated methodology. Do not present them as measured results. This workshop lets participants test the approach themselves on three modeled clouds.\n\nSource: ${article}.`);
 table(s,[['Without a shared schema','With a shared schema'],['One query per provider: N rules × M clouds','One rule on shared fields: N rules + M adapters'],['Rules hard-code eventName, methodName','Rules use semantic actions and outcomes'],['A format change breaks every copy','Fix the mapping once; rules stay the same'],['Raw quirks leak into every detection','Raw logs kept for replay and evidence']],64,180,1152,345,[576,576],25);
 text(s,'Put the complexity in the transformation, not the detection.',64,561,1120,48,30,C.amber,true);
 text(s,'Based on “Multi-Cloud Detection at Scale,” Cloud Native Detection',64,616,1120,28,18,C.muted);
}
// 3. Workshop outline.
{
 const s=slide('Workshop outline','03–04 min',`Walk through the agenda quickly. Teaching sections are short. About 30 of the 45 minutes are hands-on in the notebooks. Everyone uses EKS as the common hands-on provider. GKE and AKS examples and completed mappings are supplied so nobody has to solve all three live.\n\nSet expectations: the data is synthetic and provider envelopes are modeled. The goal is to learn the method — map, validate, write one rule, apply it to new logs — not to deploy a production pipeline. Lab 4 starts in the room and finishes at home. Lab 5 (explain one alert with source evidence) and the CTFs are take-home.\n\nSources: WORKSHOP.md; README.md.`);
 table(s,[['Time','Section','What you do'],['00–06','Background','Why normalize; three log formats; the shared contract'],['06–13','Lab 1','Read raw EKS events (notebooks 00–01)'],['13–23','Lab 2','Normalize and write one shared rule (notebook 02)'],['23–33','Lab 3','Follow the recipient from grant to secret read (notebook 03)'],['33–38','Lab 4','Start: detect service account deviations (notebook 04)'],['38–45','Debrief','What supports the detection; your next detection']],64,170,1152,440,[150,220,782],23);
}
// 4. Actual field paths, not invented provider equivalence claims.
{
 const s=slide('One behavior, three log formats','04–05 min',`Use selected field paths from the modeled workshop records. EKS and AKS cells refer to fields inside the parsed Kubernetes audit event. GKE fields are inside protoPayload. The full GKE actor path is protoPayload.authenticationInfo.principalEmail. EKS and AKS successful HTTP outcomes map to status_id=1 for codes 200–299. The modeled GKE mapping treats gRPC status zero or an omitted status as success. Missing HTTP status remains unknown. These are source-specific semantics requiring validation against actual exports.\n\nAsk: Which fields establish who acted and whether the request succeeded? Keep the discussion to one minute.\n\nThe article motivates separating source adapters from reusable detection logic. Sources: ${article}; solutions/binding_exercise/mappings.py; docs/source-validation.md.`);
 text(s,'Selected fields inside the workshop audit records',64,159,1120,38,26,C.muted);
 table(s,[['EKS','GKE','AKS'],['user.username','authenticationInfo.\nprincipalEmail','user.username'],['verb = create','methodName ends in\nclusterrolebindings.create','verb = create'],['HTTP 201','gRPC 0','HTTP 201']],64,225,1152,300,[370,412,370],26);
 text(s,'A shared outcome field carries provider-specific meaning.',64,561,1120,48,30,C.cyan);
}
// 5. Article architecture applied to the repository's real contract.
{
 const s=slide('The shared event contract','05–06 min',`Connect this to the article's raw and normalized layers: retain original evidence, validate the shared representation, then query shared fields. The workshop uses prepared local tables rather than deploying a production security lake. Schema validation needs semantic cases as well as type checks.\n\nThe minimal binding contract in notebook 02 differs from the fuller ingestion used in notebook 03, which also needs event time, secret-list events and repeated subjects. OCSF is the example schema. Students should be able to apply the contract approach to another schema.\n\nSources: ${article}; WORKSHOP.md; workshop/normalization.py; detection/privilege_to_secrets.sql.`);
 table(s,[['Preserve','Why the rule needs it'],['event_id and time','Trace evidence and order events'],['provider, account, cluster','Keep correlations on the same asset'],['principal and grant subjects','Separate the actor from the recipient'],['operation, resource, role, outcome','Express the behavior consistently']],64,190,1152,350,[455,697],27);
 text(s,'Raw records remain available for replay and investigation.',64,575,1130,38,27,C.cyan);
}
// 6. Seven minutes, one chosen cloud.
{
 const s=slide('Lab 1: Read the raw events','06–13 min / notebooks 00–01',`06–07: Run the setup cell in notebook 00 and inspect one record. Switch to notebook 01. 07–12: Work on the selected EKS raw detection only. Students identify the correct operation, resource, roleRef kind and roleRef name. Retain all asset keys and the source event ID. Supply the GKE and AKS examples rather than assigning all three exercises. 12–13: Debrief the result.\n\nThe raw exercise deliberately includes unsuccessful and unknown-outcome attempts. A match does not establish a successful access grant. Searching for a binding named cluster-admin is insufficient: inspect roleRef.\n\nCHECKPOINT: The selected-cloud binding check passes, and the student can identify the source grant event and its asset. If blocked after two minutes, reveal the collapsed hint. At 13 minutes move on with the supplied example.\n\nSources: notebooks/00_Start_here.ipynb; notebooks/01_Cloud_specific_detections.ipynb; detection/simple_cluster_admin/eks.sql; WORKSHOP.md.`);
 text(s,'Complete the EKS binding-attempt query.',64,189,1120,60,37,C.cyan,true);
 text(s,'Inspect the operation, resource and referenced role.\nRetain the source event ID and full asset scope.',64,277,1110,110,30);
 text(s,'Compare the supplied GKE and AKS examples.',64,420,1120,52,30,C.muted);
 text(s,'Checkpoint: Does a matching attempt prove access was granted?',64,548,1120,76,30,C.amber);
}
// 7. Do not reveal a completed solution before the requirements change.
{
 const s=slide('Lab 2: Normalize and write one rule','13–23 min / notebook 02',`13–14: Open notebook 02 and run setup. 14–19: Complete the EKS expressions for operation, resource_type, status_id and role using the hints. Provide the precompleted GKE and AKS dictionaries from solutions/binding_exercise/mappings.py. The notebook validator requires all providers before publishing binding_events. This is presenter preparation, not an automatic setup feature. 19–21: Validate mappings and complete the normalized binding-attempt rule. 21–23: Announce the new requirement: keep successful grants only. Ask students where to make the change. Reveal status_id = 1 only after they try.\n\nCHECKPOINT: All supplied/completed mappings validate and the shared success-only binding check passes. Failed and unknown HTTP requests must not become successful grants. Use the visible probe records to observe why match counts can change even if the enterprise log-day count does not.\n\nSources: notebooks/02_Normalize_the_logs.ipynb; solutions/binding_exercise/mappings.py; detection/simple_cluster_admin/normalized_success.sql.`);
 text(s,'Complete one provider’s mapping',64,185,1120,50,36,C.cyan,true);
 text(s,'operation     resource_type     status_id     role',64,262,1120,48,28,C.fg,false,CODE);
 text(s,'Use the supplied examples for the other two providers.\nValidate the mapping, then run the shared rule.',64,351,1120,100,30);
 text(s,'Requirements change: keep successful grants only.',64,537,1120,70,33,C.amber,true);
}
// 8. Editable evidence table presents the event sequence.
{
 const s=slide('The granted user performs the next action','23–25 min',`The following is an illustrative sequence, not a claimed observed incident. Alice grants Bob cluster-admin at 10:00. Bob lists secrets cluster-wide at 10:07. Both requests succeed on the same provider/account/cluster. The rule matches at most 15 minutes after the grant, inclusive, and only absent an exactly scoped valid approval.\n\nAsk: If Alice lists the secrets instead, does this complete Bob's grant-to-read sequence? No. If Bob reads on a different cluster, does it complete the sequence? No. The join follows the subject, not the grant actor. A successful secret-list request alone does not prove secret contents were returned or exfiltrated.\n\nSources: detection/privilege_to_secrets.sql; notebooks/03_Write_the_behavioral_rule.ipynb.`);
 table(s,[['Event time','Actor','Successful action'],['10:00','Alice','Grants Bob cluster-admin'],['10:07','Bob','Lists secrets cluster-wide']],64,203,1152,239,[220,230,702],31);
 text(s,'Same provider, account and cluster',64,487,1120,44,32,C.cyan,true);
 text(s,'0–15 minutes after the grant, inclusive',64,541,1120,44,29);
 text(s,'A secret-list request alone does not prove exfiltration.',64,606,1120,32,23,C.muted);
}
// 9. Notebook 03 supplies the rule; the exercise reads and modifies it.
{
 const s=slide('Lab 3: Follow the recipient','25–33 min / notebook 03',`25–27: Open notebook 03 and inspect the supplied grants CTE and subjects relation. 27–30: Run the supplied --save-rule cell to save main.workshop_alerts. Identify how sequences joins the subject to the read principal and preserves the full asset scope. This notebook supplies a rule to inspect and change, not an empty sequence query to implement from scratch. 30–33: Choose one alert, verify its recipient and asset, and try a smaller time window. Keep a copy of the original rule. Restore 15 minutes before saving the final version and continuing.\n\nThe later notebook uses fuller prepared ingestion, not the minimal binding-only mapping the student just completed. Person identity is optional attribution; absence must not remove native-principal matches. Exactly scoped approvals suppress only within their validity interval. The enterprise log day has no supplied validated change approvals.\n\nCHECKPOINT: One saved rule and an alert with grant_actor, subject, asset scope, grant_time and first_read. If a student has no alerts after a change, restore the supplied rule.\n\nSources: notebooks/03_Write_the_behavioral_rule.ipynb; detection/privilege_to_secrets.sql; WORKSHOP.md.`);
 text(s,'Inspect the supplied sequence rule and save it.',64,186,1120,76,36,C.cyan,true);
 text(s,'Find the subject-to-principal join.\nVerify the asset keys and event-time window.',64,289,1120,110,31);
 text(s,'Try a smaller window, then restore 15 minutes.',64,438,1120,54,30,C.muted);
 text(s,'Checkpoint: Which events support one alert?',64,551,1120,65,33,C.amber,true);
}
// 10. Lab 4 starts in the session and finishes as take-home work.
{
 const s=slide('Lab 4: Detect service account deviations','33–38 min / notebook 04',`33–34: Open notebook 04 and run setup. 34–36: Print one backup-agent record per cloud and compare where each puts the caller, account, source address, client and outcome. Point at the AWS worked example in labs/service_account_baseline/detection.sql. 36–38: Run the starter as-is and show its noisy, partly wrong deviations. Ask: which of these would you page someone for? Participants finish the GCP and Azure mappings and the seven rule fixes after the session, using the notebook's steps and collapsible hints.\n\nThis lab applies the same contract method to a new log source and a new detection class, following the article's service-account baseline example. Its deliberate blind spot is a stolen token used exactly like the baseline: a "never seen before" rule cannot see it. A deviation is a reason to investigate, not proof of compromise.\n\nSources: ${article}; notebooks/04_Detect_service_account_deviations.ipynb; labs/service_account_baseline/detection.sql.`);
 text(s,'Same method, new logs: AWS, GCP and Azure control plane.',64,189,1120,82,37,C.cyan,true);
 text(s,'Map each cloud to one contract',64,301,1120,50,31,C.fg,true);
 text(s,'Then flag actions, networks and clients a service account has never used',64,356,1120,54,27);
 text(s,'In the room: run the starter rule',64,449,1120,48,31,C.fg,true);
 text(s,'Which of its alerts would you page someone for?',64,503,1120,74,29);
 text(s,'Finish the mappings and rule fixes after the session.',64,609,1120,32,23,C.muted);
}
// 11. Debrief on semantics, not field-name normalization alone.
{
 const s=slide('What supports the detection?','38–42 min',`Ask students to explain one mistake their checks prevented. Discuss a mismatched actor, cross-cluster join, failed request, a near-matching approval, or a missing attribution link. Normalization standardizes the evidence contract; it does not eliminate behavioral logic or prove malicious intent.\n\nFor an approval to suppress the reference rule it must match provider, account, cluster, grant actor, recipient and role at grant time. The corpus for the main enterprise lab contains no validated approvals. Missing identity can limit attribution but must not remove the observed native-principal sequence. Missing logs cannot prove no access occurred. Group and ServiceAccount subjects, namespaced RoleBindings, role updates and indirect aggregation are outside the current rule's scope.\n\nSources: detection/privilege_to_secrets.yaml; detection/privilege_to_secrets.sql; docs/agent-lab.md.`);
 table(s,[['Check','Evidence required'],['Outcome','Both requests succeeded'],['Correlation','Recipient, asset and event order match'],['Suppression','An exact approval was valid at grant time'],['Investigation','Source events support each claim']],64,193,1152,335,[340,812],29);
 text(s,'Which mistake did your checks prevent?',64,566,1120,63,36,C.amber,true);
}
// 12. Close without adding the optional lab to the 45-minute clock.
{
 const s=slide('Your next detection','42–45 min',`42–43: Ask participants to name a detection they can migrate to a shared event contract. 43–44: Recap what they did: mapped one provider, compared supplied examples, ran and changed a shared binding rule, inspected a behavioral sequence, and started the service-account baseline lab. 44–45: Point to take-home work. Finish notebook 04 (about 60 minutes in total): the GCP and Azure mappings and the seven rule fixes, then the triage questions and the blind spot. Notebook 05_Investigate_alerts.ipynb is Lab 5: retrieve one alert's grant and secret-list source events and write a short evidence-backed assessment; it also offers optional local AI investigation, requiring a separate model installation and evidence verification. The easy and hard CTFs are optional, standalone practice.\n\nThe workshop is synthetic and provider envelopes are modeled. Production adaptation requires validating real exports, source semantics, logging coverage, schema changes and scheduled execution. Do not promise universal semantic equivalence or production efficacy based on the exercise.\n\nReference reading: ${article}. Repository sources: README.md; WORKSHOP.md; notebooks/04_Detect_service_account_deviations.ipynb; notebooks/05_Investigate_alerts.ipynb; ctf/README.md.`);
 text(s,'Which detection would you migrate first?',64,183,1120,91,40,C.cyan,true);
 text(s,'Take back the mapping contract, a shared SQL rule\nand a baseline rule that works across clouds.',64,306,1120,105,32);
 text(s,'Take-home: finish Lab 4, then Lab 5',64,482,1120,58,30,C.fg,true);
 text(s,'Lab 5: explain one alert with its source events\nCTFs and local AI investigation are optional follow-up work.',64,548,1120,80,25,C.muted);
}

await fs.writeFile(path.join(build,'presenter-notes.json'),JSON.stringify(notes,null,2));
const candidate=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidate);
console.log('Draft exported');
for(const [i,s] of p.slides.items.entries()){
 const png=await p.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await png.arrayBuffer()));
}
console.log('Slides rendered');
const result=await finalizePresentation({
 workspaceDir:root,candidatePath:candidate,finalPath:out,
 pythonExecutable:process.env.RUNTIME_PYTHON || path.join(os.homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3.12'),
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-bullet-geometry','--validate-heading-fit',...[2,3,4,5,8,11].flatMap(n=>['--require-native-table-slide',String(n)])],
 explicitTotalSlideCount:12,
 requiredNativeTableOwnerSlides:[2,3,4,5,8,11],requiredNativeChartOwnerSlides:[],
 fontPolicy:{basis:'design',families:[FONT,CODE]},verifyArtifactToolImport:true,
 receiptPath:path.join(build,'validation.json'),
});
console.log(JSON.stringify(result));
