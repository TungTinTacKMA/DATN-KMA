"""Small, explicit command interface; real and synthetic runs stay separate."""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
FIELDS = ['sha256','apk_path','source_id','source_version','source_label','label_binary',
          'label_evidence','package_name','group_id','collection_time','time_kind','pilot']

def save_json(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str), encoding='utf-8')

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

def environment():
    import psutil
    from .features import SCHEMA_HASH, FEATURE_SPACE_ID, FEATURE_NAMES
    packages={name:importlib.metadata.version(name) for name in
              ['androguard','numpy','scipy','pandas','scikit-learn','joblib','shap','matplotlib','streamlit','psutil','pytest']}
    r={'recorded_at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'python':sys.version,
       'executable':sys.executable,'platform':platform.platform(),'processor':platform.processor(),
       'cpu_logical':psutil.cpu_count(),'cpu_physical':psutil.cpu_count(logical=False),
       'ram_gib':round(psutil.virtual_memory().total/1024**3,2),
       'free_disk_gib':round(psutil.disk_usage(str(ROOT)).free/1024**3,2),
       'packages':packages,'feature_space_id':FEATURE_SPACE_ID,'schema_hash':SCHEMA_HASH,
       'feature_count':len(FEATURE_NAMES),'project_root':str(ROOT)}
    save_json(ROOT/'outputs/environment.json',r)
    return r

def validate_manifest(path):
    """Preflight checks provenance fields; does not certify a researcher's labels."""
    path=Path(path)
    if not path.exists(): raise ValueError(f'Khong co manifest: {path}')
    with path.open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        missing=set(FIELDS)-set(reader.fieldnames or [])
        if missing: raise ValueError('Thieu cot: '+', '.join(sorted(missing)))
        rows=list(reader)
    issues=[]; valid=0; labels={}; seen={}; pending_packages=0
    for n,row in enumerate(rows,2):
        errors=[]; key=row['sha256'].strip().lower()
        pilot=row['pilot'].strip().lower() in ('1','true','yes')
        if pilot: errors.append('PILOT_EXCLUDED')
        if len(key)!=64 or any(c not in '0123456789abcdef' for c in key): errors.append('INVALID_SHA256')
        apk=Path(row['apk_path'])
        if not apk.is_absolute(): apk=ROOT/apk
        if not apk.is_file(): errors.append('APK_NOT_FOUND')
        elif digest(apk)!=key: errors.append('HASH_MISMATCH')
        if row['label_binary'] not in ('0','1'): errors.append('LABEL_UNVERIFIED_OR_EXCLUDED')
        for field in ['source_id','source_version','source_label','label_evidence']:
            if not row[field].strip(): errors.append('MISSING_'+field.upper())
        if not row['package_name'].strip(): pending_packages+=1
        if row['source_label'].casefold()=='riskware': errors.append('RISKWARE_EXCLUDED')
        if key in seen:
            errors.append('HASH_LABEL_CONFLICT' if seen[key]!=row['label_binary'] else 'DUPLICATE_SHA256')
        seen[key]=row['label_binary']
        if errors: issues.append({'csv_line':n,'sha256':key,'reasons':errors})
        else:
            valid+=1; labels[row['label_binary']]=labels.get(row['label_binary'],0)+1
    r={'status':'ready_for_extraction' if valid and not issues and len(labels)==2 else 'needs_data_review',
       'manifest':str(path),'total_rows':len(rows),'eligible_rows_preflight':valid,
       'label_counts':labels,'issues':issues,
       'package_names_to_fill_from_extractor':pending_packages,
       'note':'Kiem tra truong va hash khong thay the doi chieu nhan voi metadata nguon.'}
    save_json(ROOT/'outputs/manifest_preflight.json',r)
    return r

def register_apks(folder, output):
    output=Path(output)
    if output.exists(): raise ValueError('Tep dich da co. Chon ten moi de khong ghi de nhan.')
    folder=Path(folder)
    if not folder.is_dir(): raise ValueError('Thu muc APK khong ton tai.')
    apks=sorted(folder.rglob('*.apk'))
    if not apks: raise ValueError('Thu muc chua co APK. Chua tao danh muc rong.')
    relative_paths=[]
    for p in apks:
        try: relative_paths.append(p.resolve().relative_to(ROOT).as_posix())
        except ValueError: raise ValueError('Hay COPY APK vao data/raw_apks truoc khi lap danh muc.')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader()
        for p,rel in zip(apks,relative_paths):
            row=dict.fromkeys(FIELDS,'')
            row.update(sha256=digest(p),apk_path=rel,pilot='false');writer.writerow(row)
    return {'status':'draft_unlabeled','samples':len(apks),'path':str(output),
            'next':'Doi chieu va dien nhan co bang chung nguon; khong suy doan nhan tu ten tep.'}

def extract_batch(manifest, output):
    from .extract import extract_apk
    with Path(manifest).open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    if not rows: raise ValueError('Manifest rong. Chua co du lieu thuc nghiem co nhan.')
    out=Path(output); out.mkdir(parents=True,exist_ok=True); summary=[]; metadata_changed=False
    for i,row in enumerate(rows,1):
        apk=Path(row['apk_path']); apk=apk if apk.is_absolute() else ROOT/apk
        print(f'[{i}/{len(rows)}] {apk.name}',flush=True)
        record=extract_apk(apk)
        record['peak_rss_mb']=record.get('evidence',{}).get('resource_limits',{}).get('peak_observed_worker_rss_bytes',0)/(1024**2)
        key=record.get('sha256') or f'failed_{i:06d}'
        save_json(out/f'{key}.json',record)
        if record.get('status')=='ok' and key==row['sha256'].strip().lower() and not row.get('package_name','').strip():
            row['package_name']=record['package_name'];metadata_changed=True
        summary.append({k:record.get(k) for k in ['sha256','status','error_code','elapsed_seconds','peak_rss_mb']})
    if metadata_changed:
        import shutil
        source=Path(manifest)
        backup=source.with_name(source.name+'.before_extraction_'+time.strftime('%Y%m%d_%H%M%S')+'.bak')
        shutil.copy2(source,backup)
        with source.open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader();writer.writerows(rows)
    save_json(out/'batch_summary.json',summary)
    return {'samples':len(rows),'statuses':{s:sum(r['status']==s for r in summary) for s in sorted(set(r['status'] for r in summary))}}

def pilot():
    from .extract import extract_apk
    out=ROOT/'outputs/pilot';out.mkdir(parents=True,exist_ok=True);records=[]
    for apk in sorted((ROOT/'data/pilot_apks').glob('*.apk')):
        print('Dang phan tich tinh:',apk.name,flush=True)
        rec=extract_apk(apk);rec['pilot']=True;rec['label_binary']=None
        rec['peak_rss_mb']=rec.get('evidence',{}).get('resource_limits',{}).get('peak_observed_worker_rss_bytes',0)/(1024**2)
        save_json(out/f'{apk.stem}.json',rec)
        records.append({'file':apk.name,'sha256':rec.get('sha256'),'status':rec['status'],
                        'error_code':rec.get('error_code'),'elapsed_seconds':rec.get('elapsed_seconds'),
                        'peak_rss_mb':rec.get('peak_rss_mb'),
                        'feature_count':len(rec.get('features') or {})})
    r={'purpose':'PARSER_PILOT_UNLABELED_NOT_CLASSIFICATION_RESULTS','records':records}
    save_json(out/'pilot_summary.json',r)
    return r

def main(argv=None):
    parser=argparse.ArgumentParser(description='Bo cong cu thuc nghiem Chuong 3. Doc README.docx truoc khi chay du lieu that.')
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ['environment','pilot','check','smoke']: sub.add_parser(name)
    reg=sub.add_parser('register-apks');reg.add_argument('--folder',default=str(ROOT/'data/raw_apks'));reg.add_argument('--output',default=str(ROOT/'data/metadata/draft_unlabeled.csv'))
    for name in ['validate','extract','build']:
        p=sub.add_parser(name);p.add_argument('--manifest',default=str(ROOT/'data/metadata/sample_manifest.csv'))
        if name in ['extract','build']:p.add_argument('--extracted',default=str(ROOT/'data/extracted'))
        if name=='build':p.add_argument('--dataset',default=str(ROOT/'data/dataset'))
    for name in ['split','train','evaluate']:
        p=sub.add_parser(name);p.add_argument('--dataset',default=str(ROOT/'data/dataset'));p.add_argument('--split',default=str(ROOT/'outputs/splits/main'))
        if name in ['train','evaluate']: p.add_argument('--run',default=str(ROOT/'outputs/runs/main'))
    p=sub.add_parser('predict');p.add_argument('--apk',required=True);p.add_argument('--model',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='environment':result=environment()
        elif args.command=='check':
            environment(); cp=subprocess.run([sys.executable,'-m','pytest','-q'],cwd=ROOT)
            return cp.returncode
        elif args.command=='pilot':result=pilot()
        elif args.command=='validate':result=validate_manifest(args.manifest)
        elif args.command=='register-apks':result=register_apks(args.folder,args.output)
        elif args.command=='extract':result=extract_batch(args.manifest,args.extracted)
        elif args.command=='build':
            from .dataset import build_dataset
            result=build_dataset(args.manifest,args.extracted,args.dataset)
        elif args.command=='split':
            from .experiment import prepare_splits
            result=prepare_splits(args.dataset,args.split)
        elif args.command=='train':
            from .experiment import train_experiments
            result=train_experiments(args.dataset,args.split,args.run)
        elif args.command=='evaluate':
            from .experiment import evaluate_run
            result=evaluate_run(args.dataset,args.split,args.run)
        elif args.command=='smoke':
            from .dataset import create_synthetic_smoke_dataset
            from .experiment import prepare_splits,train_experiments,evaluate_run
            out=ROOT/'outputs/software_smoke'/time.strftime('%Y%m%d_%H%M%S')
            create_synthetic_smoke_dataset(out/'dataset');prepare_splits(out/'dataset',out/'splits')
            train_experiments(out/'dataset',out/'splits',out/'run',smoke=True)
            result=evaluate_run(out/'dataset',out/'splits',out/'run')
        elif args.command=='predict':
            from .extract import extract_apk
            from .experiment import predict_record
            result=predict_record(extract_apk(args.apk),args.model)
        print(json.dumps(result,ensure_ascii=False,indent=2,default=str))
        if args.command=='validate' and result.get('status')!='ready_for_extraction':
            return 2
        return 0
    except (ValueError,FileNotFoundError,RuntimeError) as e:
        print('DUNG: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
