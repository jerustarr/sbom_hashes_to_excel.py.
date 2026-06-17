import pandas as pd 

with open("sbomdocument.json", encoding="utf-8") as f: 
    data = json.load(f) 

rows = [] 

for c in data.get("components", []): 
    comp_name = c.get("name") 
    version = c.get("version") 
    hash_val = None 
    hash_alg = None 

    # Extract SHA256 from licenses (fixed) 
    for lic in c.get("licenses", []): 
        lic_name = lic.get("license", {}).get("name", "") 
        if "sha256:" in lic_name: 
            hash_val = lic_name.split("sha256:")[1] 
            hash_alg = "SHA-256" 
            break 

    # Extract SHA1 from externalReferences 

    if not hash_val: 
        for ref in c.get("externalReferences", []): 
            for h in ref.get("hashes", []): 
                hash_val = h.get("content") 
                hash_alg = h.get("alg") 
                break 

            if hash_val: 
                break 
              
    # Fallback scan 
    if not hash_val: 
        for v in c.values(): 
            if isinstance(v, str) and "sha256:" in v: 
                hash_val = v.split("sha256:")[1] 
                hash_alg = "SHA-256" 
                break 


    rows.append({ 
        "Name": comp_name, 
        "Version": version, 
        "Hash": hash_val, 
        "Algorithm": hash_alg 
    }) 


df = pd.DataFrame(rows) 

# Clean 

df = df.dropna(subset=["Hash"]) 
df = df.drop_duplicates() 

# Save safely (change filename if needed) 
df.to_excel("sbom2doc_hashes.xlsx", index=False) 


print("done") 
