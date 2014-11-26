#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import unicode_literals
import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.options
import tornado.web
from twython import Twython
import tweepy
from tornado.options import define, options
import secrets
from random import randint
import subprocess
import pexpect
import os
import tornado.auth
import oauth2 as oauth
import json
from collections import defaultdict
import urlparse

define("port", default=8888, help="run on the given port", type=int)

tokenDict = {}
counter = 1

consumer_key = secrets.CONSUMER_KEY
consumer_secret = secrets.CONSUMER_SECRET

pub_remote_ip = []
sub_remote_ip = []


 
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")

class TwitterHandler(tornado.web.RequestHandler):
    def get(self):
        if self.get_argument("oauth_token", None):
            for val in tokenDict:
                if tokenDict[val]['oauth_token'] == self.get_argument("oauth_token", None):
                    oauth_token = tokenDict[val]['oauth_token']
                    oauth_token_secret = tokenDict[val]['oauth_token_secret']
                    token = oauth.Token(oauth_token, oauth_token_secret)
                    token.set_verifier(self.get_argument("oauth_verifier", None))
                    
                    tokenDict[val]['oauth_verifier'] = self.get_argument("oauth_verifier", None)
                    consumer = tokenDict[val]['consumer'] 
                    client = oauth.Client(consumer,token)
                    resp, content = client.request("https://twitter.com/oauth/access_token", "POST")
                    access_token = dict(urlparse.parse_qs(content))
                    tokenDict[val]['oauth_token_final'] = ", ".join(access_token['oauth_token'])
                    tokenDict[val]['oauth_token_secret_final'] = ", ".join(access_token['oauth_token_secret'])
                    print tokenDict
                    if "screen_name" in access_token:
                        screen_name = ", ".join(access_token.get('screen_name'))
                        tokenDict[val]['screen_name'] = screen_name
                        #print tokenDict
			self.render("static/homePage.html")
                        return 
                    else:
                        print "screen_name not found!"

                else:
                        print "Did not find oauth token"  
        else:
             global counter
             tokenDict[str(counter)] = tokenDict.get(str(counter), {})

             consumer = oauth.Consumer(consumer_key, consumer_secret)
             tokenDict[str(counter)]['consumer'] = consumer
             client = oauth.Client(consumer)

             resp, content = client.request("https://api.twitter.com/oauth/request_token", "GET")
             request_token = dict(urlparse.parse_qsl(content)) 
             oauth_token = request_token['oauth_token']
             oauth_token_secret = request_token['oauth_token_secret']
             #print "oauth_token: %s"%oauth_token
             #print "oauth_token_secret: %s"%oauth_token_secret
             tokenDict[str(counter)]['oauth_token'] = oauth_token
             tokenDict[str(counter)]['oauth_token_secret'] = oauth_token_secret
             #print tokenDict
             counter = counter + 1
             self.finish(json.dumps(oauth_token))

    def _on_auth(self, user):
        #print user
        if not user:
            raise tornado.web.HTTPError(500, "Twitter auth failed")
        # Save the user using, e.g., set_secure_cookie()

class NameHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print "new connection"

    def on_message(self,data):
        print "data received from server is: %s"% data

        data = dict(urlparse.parse_qsl(data))
        oauth_token = data['oauth_token']
        for val in tokenDict:
            if tokenDict[val]['oauth_token'] == oauth_token:
                screen_name = tokenDict[val]['screen_name']
                break        
        
        if not screen_name:
            self.write_message("not found")
        else: 
            self.write_message(screen_name)

    def on_close(self):
        self.close()
        print 'connection closed' 


class PostTweetHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print 'new connection'
        #self.write_message("opened connection")
      
    def on_message(self, data):
        print "data received from server is: %s"% data

        data = dict(urlparse.parse_qsl(data))
        print data
        tweet = data['tweet']
        oauth_token = data['oauth_token']

        #print oauth_token
        #print tweet

        for val in tokenDict:
            if tokenDict[val]['oauth_token'] == oauth_token:
                 rand_int = randint(0,100)
                
                 twitter = Twython(app_key=consumer_key, app_secret=consumer_secret,oauth_token=tokenDict[val]['oauth_token_final'],oauth_token_secret=tokenDict[val]['oauth_token_secret_final'])
                 
                 twitter.update_status(status=tweet) 
                 print "tweeted successfully!"
                 break
                  
        self.write_message("http://10.23.0.18:8888/pubs?mult_no=%s"% rand_int)
 
    def on_close(self):
        self.close()
        print 'connection closed'
           
class PubSubHandler(tornado.web.RequestHandler):
    def get(self):
        global pub_remote_ip
        global sub_remote_ip
        
        req_uri = self.request.uri
        url =  dict(urlparse.parse_qsl(req_uri)) 

        if('pubs' in req_uri):

            multicast_no = url['/pubs?mult_no']
            oauth_token =  url['oauth_token']

            pub_remote_ip.append(str(self.request.remote_ip))
            status = 'Subscribers enter link: http://10.23.0.18:8888/subs?mult_no=%s&way=enter and leave link: http://10.23.0.18:8888/subs?mult_no=%s&way=leave'%(multicast_no, multicast_no)
            for val in tokenDict:
                if tokenDict[val]['oauth_token'] == oauth_token:
                    twitter = Twython(app_key=consumer_key, app_secret=consumer_secret,oauth_token=tokenDict[val]['oauth_token_final'],oauth_token_secret=tokenDict[val]['oauth_token_secret_final'])
                    twitter.update_status(status=status)
                    self.render("static/gotPub.html") 
                    break           

        elif('subs' in req_uri):
            way = url['way']
            
            if( way == 'enter'):
            	sub_remote_ip.append(str(self.request.remote_ip))
            elif (way == 'leave'):	
                if str(self.request.remote_ip) in sub_remote_ip:
                    sub_remote_ip.remove((str(self.request.remote_ip)))
                else: 
                    print "Cannot find the IP address from the list to remove!"
            
            self.render("static/gotSub.html")
        else:
            print "just a web server"

        pub_remote_ip = list(set(pub_remote_ip))
        sub_remote_ip = list(set(sub_remote_ip))

        if pub_remote_ip and sub_remote_ip:
            print "got Both pub and sub"
            print "Pub_remote_ip List:"
            print pub_remote_ip
            print "Sub_remote_ip List: "
            print sub_remote_ip
            try:
                child = pexpect.spawn("ssh stack@10.10.200.10 python /home/stack/kaleidoscope_multicast_alg/start.py "+str(pub_remote_ip)+" "+str(sub_remote_ip))
                child.expect("stack@10.10.200.10's password:")
                child.sendline("stackstack")
                child.interact()
            except OSError:
                pass

        else:
            print "didn't get both"




class IndexPageHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")

def main():
    tornado.options.parse_command_line()
    settings = {
        "static_path": os.path.join(os.path.dirname(__file__), "static"),
        "login_url": "/auth/login",
        "xsrf_cookies": False,
    }

    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/index.html", IndexPageHandler),
        (r"/authenticate", TwitterHandler),
        (r"/name", NameHandler),
        (r"/ws",PostTweetHandler),
        (r"/pubs", PubSubHandler),
        (r"/subs", PubSubHandler),
    ], **settings)

    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port, "10.23.0.18")
    #http_server.listen(options.port)

    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == "__main__":

    main()

