import os, sys, yara, argparse, hashlib
from discord_webhook import DiscordWebhook
from time import sleep
from tqdm import tqdm

sys.path.insert(1, "sources")

parser = argparse.ArgumentParser(description="YaraMonitor: Monitor malware sources with a set of Yara rules")
parser.add_argument("-d", "--discord", type=str, help="Send results to Discord Webhook provided")
parser.add_argument("-w", "--wipe", action="store_true", help="Remove existing files from samples directory when the script starts")
args = parser.parse_args()
discord = args.discord
wipe = args.wipe

def run_ingestion():
    import malwareBazaar
    malwareBazaar.main()

def index_rules():
    files = set()
    for file in os.listdir("rules"):
        files.add(file)
    return files

def load_rule(file):
    with open(file) as f:
        src = f.read()
    rule = yara.compile(source=src)
    return rule

def index_samples():
    files = set()
    for dir in os.listdir("samples"):
        for file in os.listdir(f"samples/{str(dir)}"):
            files.add(str(f"samples/{str(dir)}/{str(file)}"))
    return files

def alert(rule, sample):
    message = f"[+] {str(rule)} triggered on {str(sample)}"
    print(message)
    DiscordWebhook(url=discord, content=message).execute()

def remove_samples(samples_matched):
    samples = index_samples()
    for sample in samples:
        hash_object = hashlib.sha256(sample.encode())
        hex_dig = hash_object.hexdigest()
        if hex_dig not in samples_matched:
            print(f"[+] Removing {str(sample)}")
            os.remove(sample)

def main():
    global samples_scanned
    samples_scanned = set()
    global samples_matched
    samples_matched = set()
    if wipe:
        remove_samples(samples_matched)
    while True:
        run_ingestion()
        rules = index_rules()
        samples = index_samples()
        hash_list_buf = set()
        for rule in rules:
            try:
                yara_rule = load_rule("rules/" + rule)
            except yara.SyntaxError: # not sure why this happens, it is inconsistent; also, loading all rules at once fails
                continue
            for sample in samples:
                hash_object = hashlib.sha256(sample.encode())
                hex_dig = hash_object.hexdigest()
                if hex_dig in samples_matched:
                    continue
                # Temporary buffer of samples scanned in this loop
                hash_list_buf.add(hex_dig)
                print(f"[+] Scanning {str(sample)} with {str(rule)}")
                yara_matches = yara_rule.match(sample)
                samples_scanned.add(hex_dig)
                if len(yara_matches) > 0:
                    alert(rule, sample)
                    samples_matched.add(hex_dig)
        # keep track of samples scanned for the lifetime of the program
        samples_scanned = samples_scanned | hash_list_buf
        print("[+] Scanned all files!")
        print("[+] Removing those without a yara match")
        remove_samples(samples_matched)
        print("[+] Sleeping for 1 minute...")
        for i in tqdm(range(60)):
            sleep(1)

main()