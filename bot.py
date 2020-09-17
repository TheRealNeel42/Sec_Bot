import discord
import base64
import requests
import json
import re
import asyncio
import urllib.parse
from os import path
from discord.ext import commands
from discord import Webhook, RequestsWebhookAdapter
import aiohttp

bot = commands.Bot(command_prefix='>')
bot_token = ''
hibp_key = ''
ipstack_key = ''

data = ""
if not path.exists('config.json'):
    print("Config file not found, exiting...")
    exit()


with open('config.json') as f:
    _config = json.load(f)

bot_token = _config["bot_token"]
hibp_key = _config["hibp_key"]
ipstack_key = _config["ipstack_key"]



@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')

@bot.event
async def on_message(message):
    # do some extra stuff here
    logged_message= str(message.author) + " sent: " + str(message.content)
    #print(logged_message)
    await bot.process_commands(message)

@bot.command()
async def test(ctx):
    response = "Test Successfull, " + str(bot.user) + " is online"
    await ctx.send(response)

@bot.command()
async def encode64(ctx, args):
    raw_string = args
    message_bytes = raw_string.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    final = base64_bytes.decode('utf-8')
    await ctx.send(final)

@bot.command()
async def decode64(ctx, args):
    data = base64.b64decode(str(args))
    final = data.decode('utf-8')
    await ctx.send(final)

@bot.command()
async def cve(ctx, *, args):
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=" + urllib.parse.quote(str(args))
    r = requests.get(url)
    cve = json.loads(r.text)
    
    if 'result' in cve.keys():
        embed = discord.Embed(title="Top 5 CVE Listing", color=discord.Color.blue())
        for x in cve['result']['CVE_Items'][:5]:
            cve_id = str(x['cve']['CVE_data_meta']['ID'])
            cve_description = str(x['cve']['description']['description_data'][0]['value'][0 : 300])
            cve_url = "[Click here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + urllib.parse.quote(str(x['cve']['CVE_data_meta']['ID'])) + ")"
        
            embed.add_field(name="CVE:", value=cve_id)
            embed.add_field(name="Description", value=cve_description)
            embed.add_field(name="Link", value=cve_url)
           
        await ctx.send(embed=embed)
    else:
        await ctx.send("No match found")

@bot.command()
async def haveibeenpwned(ctx, args):
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(str(args))
    HEADERS = {"hibp-api-key" : hibp_key}

    r = requests.get(url, headers=HEADERS)
    if(r.text):
        pwned = json.loads(r.text)

        num_breaches = len(pwned)
        title = "Account Comprised in " + str(num_breaches) + " breaches:"
        embed = discord.Embed(title=title, color=discord.Color.blue())
        for x in pwned:

            breach = str(x['Name'])
            breach_url = "https://haveibeenpwned.com/api/v3/breach/" + urllib.parse.quote(breach)
            b = requests.get(breach_url, headers=HEADERS)
            breachdata = json.loads(b.text)
            breach_date = str(breachdata['BreachDate'] + "\n")
            breach_description = str(breachdata['DataClasses'])+ "\n"
            embed.add_field(name="Breach Name: ", value=breach)
            embed.add_field(name="Breach Date: ", value=breach_date)
            embed.add_field(name="Data Breached: ", value=breach_description)
        await ctx.send(embed=embed)
    else:
        await ctx.send("No breach found")

#CTFs are hard. here is some encouragement
@bot.command()
async def encourage(ctx):
    url = "https://www.affirmations.dev/"
    r = requests.get(url)
    affirmation = json.loads(r.text)
    await ctx.send(affirmation['affirmation'])

@bot.command()
async def ip(ctx, args):
    url = "http://api.ipstack.com/"+ urllib.parse.quote(str(args))+"?access_key=" + ipstack_key +"&fields=ip,country_name,region_name,city,zip,latitude,longitude"
    r = requests.get(url)
    iplocation= json.loads(r.text)
    mapurl = "[Click to view in Google maps](https://www.google.com/maps/@"+str(iplocation['latitude']) + "," + str(iplocation['longitude']) + ",5z)"
    embed = discord.Embed(title="IP Geolocation for " + str(args), color=discord.Color.blue())
    embed.add_field(name="Country Name: ", value=iplocation['country_name'])
    embed.add_field(name="Region Name: ", value=iplocation['region_name'])
    embed.add_field(name="City: ", value=iplocation['city'])
    embed.add_field(name="Zip Code: ", value=iplocation['zip'])
    embed.add_field(name="Map View: ", value=mapurl)
    await ctx.send(embed=embed)
  

@bot.command()
async def urlencode(ctx, *, args):
    encoded_string = urllib.parse.quote(str(args))
    await ctx.send(encoded_string)  


bot.run(bot_token)