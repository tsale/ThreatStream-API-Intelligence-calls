import requests
import logging as log
import colorama
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i','--indicator', help='Specify your indicator', required=True)
parser.add_argument('-u','--user', help='Specify your Username', required=False)
parser.add_argument('-k','--key', help='Specify your API KEY', required=False)
args = parser.parse_args()
query = args.indicator
apiuser = args.user
apikey = args.key

if (apiuser and apikey) == None:
  apikey = '' # Specify Username HERE Or Specify on the commandline
  apiuser= '' # Specify APIKEY HERE Or Specify on the commandline
query_api_url = 'https://api.threatstream.com/api/v2'

red = colorama.Fore.RED
green = colorama.Fore.GREEN
yellow = colorama.Fore.YELLOW
cyan = colorama.Fore.CYAN
reset = colorama.Fore.RESET

def query_api(apiuser,apikey,resource,flags):
    url = '{}/{}/?username={}&api_key={}{}'.format(query_api_url, resource, apiuser, apikey, flags)
    try:
      http_req = requests.get(url, headers={'ACCEPT': 'application/json, text/html'})
      if http_req.status_code == 200: return(http_req.json()['objects']) # Return JSON Blob
      elif http_req.status_code == 401: 
        log.error('Access Denied. Check API Credentials')
        exit(0)
      else: log.info('API Connection Failure. Status code: {}'.format(http_req.status_code))
    except Exception as err:
      log.error('API Access Error: {}'.format(err))
      exit(0)


def repcheck(apiuser,apikey, *args):
    response = []
    limit = 200 # Limit number of responses
    status = "active" 
    response.append(query_api(apiuser,apikey,'intelligence',
      '&extend_source=true&value__re=.*{}.*&limit={}&status={}'.format(query, limit, status)))
    return(response)

def format_output(jsonblob):
  r = ""
  for line in jsonblob:
      for k, v in line.items():
        if not v: continue
        r += "{}: {}\n".format(k, v)
  return(r)

def indicators():
    itypes = []
    for parse in full_response[0]:
        itypes.append(parse['itype'])
    itypes = list(set(itypes))
    print(yellow,"_"*8)
    print(yellow,"| ",green,"Indicators Found: {}{}".format(cyan,len(full_response[0])))
    print(yellow,"| ",green,"Types of indicators found: {}{}".format(cyan,itypes))
    print(yellow,"_"*8+"\n",reset)
    case = 0
    for parse in lim_response:
        case += 1
        print(reset,f"{case}/{cyan}5",reset + "\n")
        print(green,"Created: {}{}".format(red,parse['created_ts']),colorama.Fore.RESET)
        print(green,"Indicator: {}{}".format(red,parse['value']))
        print(green,"Type: {}{}".format(red,parse['threat_type']))
        print(green,"Source: {}{}\n".format(red,parse['source']))
        print(green,"Reported Severity: {}{}".format(red,parse['meta']['severity']))
        print(green,"IP: {}".format(parse['ip']))
        print(green,"TS Confidence = {0}{1}{2} <----> {3}Source Confidence = {4}{5}"
              .format(red,parse['confidence'],reset,green,red,parse['source_reported_confidence']))
        print(reset,"\n")
        print(colorama.Back.YELLOW,"Tags: ",colorama.Back.RESET)
        try:
            x = 0
            for tag in parse['tags']:
                x += 1
                print(red,"\t\t====>".ljust(28),reset, end=f" ")
                print("{0}. {1}".format(x,tag['name']))
        except TypeError:
            print("No tags\n")
        print("\n"+colorama.Back.LIGHTCYAN_EX, "="*100,colorama.Back.RESET,"\n\n")


if __name__ == '__main__':
    full_response = (repcheck(apiuser, apikey, query))
    lim_response = (full_response[0][:5])
    indicators()