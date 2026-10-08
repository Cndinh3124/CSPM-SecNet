import os,subprocess
def run(region,out):
 out.mkdir(parents=True,exist_ok=True)
 cmd=os.getenv("PROWLER_COMMAND","prowler")
 r=subprocess.run([cmd,"aws","--region",region,"--output-directory",str(out)],text=True,capture_output=True)
 (out/"stdout.log").write_text(r.stdout,encoding="utf-8")
 (out/"stderr.log").write_text(r.stderr,encoding="utf-8")
 if r.returncode: raise RuntimeError(f"Prowler failed: {r.returncode}; see {out/'stderr.log'}")
