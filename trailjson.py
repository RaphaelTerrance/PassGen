import json
with open ('fetish.json','r+') as file:
    t=json.load(file)
    t['anamay'].append('fih')
    json.dump(t,file,indent=4)
    #print(t)

print(t['anamay'][2])