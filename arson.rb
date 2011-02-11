require 'rubygems'
require 'broach'
require 'daemons'
require "yajl/http_stream"
require 'logger'
require 'xmpp4r'
require 'xmpp4r/muc'
require 'xmpp4r/roster'

def fix_nicks( room )
end

Daemons.run_proc('camfire_jabber_hack',
                :dir_mode => :script,
                :monitor => true,
                :log_output => true
                ) do

  # BEGIN CHANGE SECTION

  # CHANGEME: This is your campfire API token; see
  #
  # http://developer.37signals.com/campfire/
  campfire_token = '98a9607eadfd2fe3173e9cb032b1e5dacd1dce15'

  jabber_com_name = 'campfire.localhost'
  jabber_com_host = 'localhost'
  jabber_com_pass = 'campfirepass'

  # CHANGEME: Your campfire room/jabber information
  #
  # Pairs of campfire rooms, and the jabber user to emit their
  # messages as
  rooms = [
    # Each room has a jabber segment and a campfire segment
    {
      # The campfire information
      :campfire => {
        # The campfire room to listen in
        :room => "Support",
        # The campfire domain
        :domain => 'engineyard.campfirenow.com',
        # Use ssl?
        :ssl => true,
        # Any message from a campfire user with this name is
        # ignored. Setting this to your own Campfire name is
        # important, because otherwise you'll get your own messages
        # coming back to you.
        :self_name => "Robin Powell",
      },
      # The jabber information
      :jabber => {
        # The jabber user to login in as.  Every message from the
        # campfire room is sent from this jabber user,
        :user => 'ey-cf-support@localhost',
        :pass => 'password',
        # The jabber user to send the messages to.
        :deliver_to => 'rpowell@localhost',
      },
    },
    # Other rooms, more compact
    {
      :jabber => {:user => 'ey-cf-sam@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
      :campfire => {:room => "SAM", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
    },
    {
      :jabber => {:user => 'ey-cf-sysadmin@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
      :campfire => {:room => "Sysadmin", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
    },
#    {
#      :jabber => {:user => 'ey-cf-spam@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
#      :campfire => {:room => "Spam", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
#    },
    {
      :jabber => {:room => 'COMey-cf-testing@conference.localhost'},
      :campfire => {:room => "Testing", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Wibble" }
    },
  ]

  # END CHANGE SECTION

  log = Logger.new(STDERR)
  log.level = Logger::INFO

  Broach.settings = {
    'account' => 'engineyard',
    'token'   => campfire_token,
    'use_ssl' => true
  }

  my_campfire_id = Broach.session.get("users/me.json")['user']['id']

  require "rubygems"
  require "uri"
  require "yajl/http_stream"

  token = '98a9607eadfd2fe3173e9cb032b1e5dacd1dce15'
  room_id = 151388

  url = URI.parse("http://#{token}:x@streaming.campfirenow.com/room/#{room_id}/live.json")
  begin
  Yajl::HttpStream.get(url) do |message|
      puts message.inspect
  end
      rescue SystemExit
        exit
      rescue Exception => e
        log.info( "detached from room #{room[:campfire][:room]} via error: #{e.inspect}" )
        room[:check_counter] = 999999
      end

    jabber_component = Component::new(jabber_com_name, jabber_com_host)
    jabber_component.connect
    jabber_component.auth(jabber_com_pass)

  # setup
  rooms.each do |room|
    fix_nicks( room )

    jabber_mucs = Hash.new
    jabber_mucs['&master'] = Jabber::MUC::SimpleMUCClient.new(jabber_component)
    jabber_mucs['&master'].my_jid = Jabber::JID.new('comtest1@campfire.localhost')
    jabber_mucs['&master'].join(Jabber::JID.new('cjh2_test_chat@conference.localhost/weatherbotcom1'))
    jabber_mucs['&master'].say( "foobar" )

    at_exit do
      @mucs.keys.each do |key|
        @mucs[key].exit()
      end
    end

            room_info = Broach.session.get("room/#{campfire_room_id}.json")
            log.debug("room: #{room_info['room']['users'].inspect}")

            names = 'USER LIST: '
            room_info['room']['users'].each do |user|
              names += "#{user['name']} ---- "
            end

            im.deliver(room[:jabber][:deliver_to], names)


      jabber_muc = Jabber::Simple.new(room[:jabber][:user], room[:jabber][:pass])
      # If you don't wait, jabber might not notice you
      sleep 5;
      im.add(room[:jabber][:deliver_to]);

      room[:im] = im

      room[:last_message] = 0

      room[:check_counter] = 999999

      room[:campfire_room] = Broach::Room.find_by_name( room[:campfire][:room] )
  end

  while true
    rooms.each do |room|
      if room[:campfire_room] == nil
        log.error( "Room #{room[:campfire][:room]} doesn't seem to be working in Broach; perhaps the name is wrong?" )
        break
      end

      log.debug( "Working on room #{room[:campfire][:room]}" )

      campfire_room = room[:campfire_room]
      campfire_room_id = room[:campfire_room].id

      im = room[:im]

      #************************************************
      # Campfire => Jabber Section
      #************************************************
      begin
        log.debug("room counter: #{room[:check_counter]}")
        if room[:check_counter] > 2
          log.debug("checking room")
          log.debug("check 1: #{Broach.session.get("presence.json")['rooms'].inspect} should include id #{campfire_room_id}");
          log.debug("check 2: #{Broach.session.get("room/#{campfire_room_id}.json")['room']['users']} should include id #{my_campfire_id}");
          if room[:check_counter] > 10 or
            ! Broach.session.get("presence.json")['rooms'].detect{ |x| x['id'] == campfire_room_id} or
            ! Broach.session.get("room/#{campfire_room_id}.json")['room']['users'].detect{ |x| x['id'] == my_campfire_id} then

            log.info( "attaching to room #{room[:campfire][:room]}, id #{campfire_room_id}" )

            # This logs us in to the room.  We re-run it
            # periodically because we seem to fall out otherwise.
            #
            # Broach can't handle POST calls that return a flat 200,
            # which is a problem since the API does this repeatedly.
            #
            # FIXME:  Update the next line when that broach bug is
            # fixed
            REST.post(Broach.session.url_for("room/#{campfire_room_id}/join"), '', Broach.session.headers_for(:post), Broach.session.credentials)

            room[:check_counter] = 0
          end
        end

        log.debug("pre-messages")
        messages = Broach.session.get("room/#{campfire_room_id}/recent.json?limit=5&since_message_id=#{room[:last_message]}")['messages']
        log.debug("messages: #{messages.inspect}")

        messages.each do |message|
          if( message['body'] && message['id'] > room[:last_message] ) then
            user_name=Broach.session.get("users/"+message['user_id'].to_s)['user']['name']
            if( user_name != room[:campfire][:self_name] ) then
              log.debug("sending --#{user_name}: #{message['body']}-- to #{room[:jabber][:deliver_to]}")
              im.deliver(room[:jabber][:deliver_to], "#{user_name}: #{message['body']}")
            end
          end
          room[:last_message] = message['id']
        end
        log.debug("pre-sleep")
        room[:check_counter] += 1
        log.debug("post-sleep")
      rescue SystemExit
        exit
      rescue Exception => e
        log.info( "detached from room #{room[:campfire][:room]} via error: #{e.inspect}" )
        room[:check_counter] = 999999
      end

      #************************************************
      # Jabber => Campfire Section
      #************************************************
      begin
        im.received_messages do |msg|
          if msg.body == "USER LIST" then
            log.debug( "roomid: #{campfire_room_id}.xml" )
            room_info = Broach.session.get("room/#{campfire_room_id}.json")
            log.debug("room: #{room_info['room']['users'].inspect}")

            names = 'USER LIST: '
            room_info['room']['users'].each do |user|
              names += "#{user['name']} ---- "
            end

            im.deliver(room[:jabber][:deliver_to], names)
          else
            log.debug("sending #{msg.body} to #{room[:campfire][:room]}")
            Broach.speak( room[:campfire][:room], msg.body ) if msg.type == :chat 
          end
        end
      rescue SystemExit
        exit
      rescue Exception => e
        log.info( "error #{e.inspect} received while checking for IM messages for #{room[:campfire][:room]}" )
      end

      #sleep 0.3
    end
  end
end
