import csv 
import time
import calendar

files = {
    'email': 'email.csv',
    'url': 'url.csv',
    'ip': 'ip.csv'
}
output_file = f'sample-events-{calendar.timegm(time.gmtime())}.txt'

data = {}

for file in files:
    with open(files[file]) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        data[file] = []
        for row in csv_reader:
            data[file].append(row[0]) 
    csv_file.close()

with open(output_file, mode='w') as output_f:
    for i in range(0, len(data['email'])):
        if(i < len(data['email']) and i < len(data['url']) and i < len(data['ip'])):
            output_f.write(f"{calendar.timegm(time.gmtime())} email_address={data['email'][i]} src_ip={data['ip'][i]} redirect_url={data['url'][i]}\n")
output_f.close()