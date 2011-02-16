# General Design:
#
# The Jabber End:
# 
# We create a jabber component, campfire.localhost or similar, use it
# to create a MUC for each campfire room, and also use it to create
# virtual users to join the MUCs, one for each campfire user.
# 
# Every Jabber MUC has a master user (called "virt_campfire") in it, with
# a callback.  When a message is generated on the Jabber end, the
# callback checks to see if it came from any of the virtual users we
# created.  If it doesn't, we use the name that it came in on to find
# a Campfire user name to send it out as.
# 
# FIXME: this means we should allow multiple campfire users.
# 
# The Campfire End:
# 
# We log in to Campfire with the token(FIXME: s).  Then we make a
# thread for each room, and stream messages in that thread.  Any kick
# or leave or join message causes the list of MUC virtual users to get
# re-evaluated.  Any actual message gets passed to the Jabber room.
# 
# We also launch another thread that simply re-asserts each token's
# presence in each room every minute, because Campfire has this
# annoying habit of losing track.


require 'rubygems'
require 'broach'
require 'daemons'
require 'uri'
require 'yajl/http_stream'
require 'logger'
require 'xmpp4r'
require 'xmpp4r/muc'
require 'xmpp4r/component'
require 'xmpp4r/roster'
require 'yaml'
require 'ArsonConfig'

$jabber_component = nil

$log = Logger.new(STDERR)

$rooms = ArsonConfig::Rooms
$log.debug( "Config load: Rooms: #{YAML::dump($rooms)}" )

$users = Array.new

ArsonConfig::Configs.each do |configfile|
  $users.push( YAML.load_file(configfile) )
end

$log.debug( "Config load: Users: #{YAML::dump($users)}" )

def send_presence( from, to, type, xmuc=false, affiliation=nil, role=nil, reason=nil, status_codes=nil )
  $log.debug( "In send_presence: #{from}, #{to}, #{type}, #{xmuc}, #{affiliation}, #{role}, #{reason}, #{status_codes}" )
  presence = Jabber::Presence.new.set_from( from )
  presence.set_to( to ).set_type( type )

  if xmuc
    xelem = presence.add_element('x', { 'xmlns' => 'http://jabber.org/protocol/muc#user' } )
    print "presence: #{YAML::dump(presence)}\n"

    if affiliation and role
      itemelem = xelem.add_element( 'item', { 'affiliation' => affiliation, 'role' => role } )
      if reason
        itemelem.add_element( 'reason' ).add_text( reason )
      end
      print "presence: #{YAML::dump(presence)}\n"
    end

    if status_codes
      status_codes.each do |code|
        xelem.add_element( 'status', { 'code' => code } )
      end
      print "presence: #{YAML::dump(presence)}\n"
    end

    $jabber_component.send(presence)
  end
end

# Drop all the virtual users when we exit
at_exit do
  $users.each do |user|
    user['rooms'].each do |room|

      room_jid=nil
      if room.has_key?('room_jid')
        room_jid=room['room_jid']
      else
        room_jid="#{room['campfire_room_name']}@#{ArsonConfig::JabberComponentName}"
      end

      user_jid=nil
      if room.has_key?('user_jid')
        user_jid=room['user_jid']
      else
        user_jid=user['jabber_id']
      end

      send_presence( room_jid, user_jid, :unavailable, true, 'none', 'none', 'Campfire server shutting down.', [ '307' ] )
    end
  end
end

# function fix_nicks(room)
#
# First we grab all the users in the room
#
# Then we loop through all the users in the room and make sure they
# exist in the MUC
#
# Then we loop through all the users in the MUC and make sure they
# exist in the room.
#
# There's certainly better ways to do that (like set substraction),
# but we're talking about very small lists so enh.
#
def fix_nicks( room, realuser )
  campfire_room = room['campfire_room']
  campfire_room_id = room['campfire_room'].id

  room_info = room['broach_session'].get("room/#{campfire_room_id}.json")
#  $log.debug("users in room: #{room_info['room']['users'].inspect}")

  # Check that every room user has a MUC equivalent
  room_info['room']['users'].each do |user|
    uname = user['name']
    # The second part here is to ignore the real user's campfire name
    if ! room['jabber_users'][uname] and room['campfire_user_name'] != uname then
      make_muc_user( room, realuser, uname )
    end
  end

  # Check that every MUC user is still in the Campfire room
  room['jabber_users'].keys.each do |uname|
    if ! room_info['room']['users'].find { |user| user['name'] == uname }
      drop_muc_user( room, uname )
    end
  end
end

def name_to_jabber_nick( name, room )
  usename = name
  if room['jabber_users'].has_key?( name )
    usename = room['jabber_users'][name]
  end
  return slugify_name( usename )
end

def slugify_name( name )
  return name.gsub(/-+\&$/,'')
end

# Just the first word
def name_first( name )
  return name.split[0]
end

# Just the first word and the first letter of the next word
def name_firstni( name )
  return name.split[0]+" "+name.split[1][0,1]
end

def preferred_name( type, name )
  $log.debug( "In preferred_name; type #{type}, name #{name}" )
  case type
  when "first"
    return name_first( name )
  when "firstni"
    return name_firstni( name )
  when "all"
    return name
  else
    $log.fatal( "Invalid name handling type #{type}; check the user config files." )
    exit 1
  end
end

def check_name_conflict( name, room )
  $log.debug( "In check_name_conflict, name #{name}, room names #{YAML::dump(room['jabber_users'])}" )
  conflict = false
  conflict = room['jabber_users'].keys.detect { |fullname| room['jabber_users'][fullname] == name }
  $log.debug( "In check_name_conflict, returning #{conflict}" )
  return conflict
end


def make_muc_user_final( room, usename )
  from = "#{room['campfire_room_name']}@#{ArsonConfig::JabberComponentName}/#{slugify_name(usename)}"

  $log.debug( "in make_muc_user: from: #{from}" )

  send_presence( from, room['user_jid'], nil, true, 'member', 'participant' )
end

def make_muc_user( room, user, uname )
  $log.debug( "in make_muc_user: orig name: #{uname}\n" )

  print "User dn: #{user['default_names']}"
  print "User dn: #{user['similar_names:']}"
  print "User : #{user}"
  # Figure out what the final name actually looks like.
  usename = nil
  wantname = preferred_name( user['default_names'], uname )
  if check_name_conflict( wantname, room )
    secondwantname = preferred_name( user['similar_names'], uname )
    if check_name_conflict( secondwantname, room )
      # Default to "All"; since we already tested based on uname,
      # which is what we store in the hash, there should be no
      # conflict here

      # The first version wasn't OK; so change whoever the
      # collission was with
      conflictfullname = check_name_conflict( wantname, room )
      drop_muc_user( room, conflictfullname )

      room['jabber_users'][conflictfullname] = conflictfullname

      make_muc_user_final( room, conflictfullname )

      # Save the new user's nick name
      usename = uname
    else
      # The first version wasn't OK; so change whoever the
      # collission was with
      conflictfullname = check_name_conflict( wantname, room )
      conflictnewname = preferred_name( user['similar_names'], conflictfullname )
      drop_muc_user( room, conflictfullname )

      room['jabber_users'][conflictfullname] = conflictnewname

      make_muc_user_final( room, conflictnewname )

      # Save the new user's nick name
      usename = secondwantname
    end
  else
    # Save the new user's nick name
    usename = wantname
  end

  room['jabber_users'][uname] = usename

  make_muc_user_final( room, usename )
end

def drop_muc_user( room, uname )
  $log.debug( "in drop_muc_user: orig name: #{uname}\n" )
  from = "#{room['campfire_room_name']}@#{ArsonConfig::JabberComponentName}/#{name_to_jabber_nick(uname, room)}"

  send_presence( from, room['user_jid'], :unavailable, true, 'none', 'none' )

  room['jabber_users'].delete(uname)
end

def send_to_jabber( room, uname, msg )
  $log.debug("sending #{msg} to jabber room #{room['room_jid']}")

  from = "#{room['campfire_room_name']}@#{ArsonConfig::JabberComponentName}/#{name_to_jabber_nick(uname, room)}"
  jmess = Jabber::Message.new( room['user_jid'], msg ).set_from( from ).set_type(:groupchat)
  $jabber_component.send(jmess)
end

def send_to_campfire( room, msg )
  $log.debug("sending #{msg} to campfire room #{room[:campfire][:room_name]}")
  Broach.speak( room[:campfire][:room_name], msg )
end

#*************************
# This is the "make sure camfire knows we're here" section.
#*************************
def stay_in_campfire_room( room, user )
  th = Thread.new do
    begin
      while true
        $log.debug("checking room")
#        $log.debug("check 1: #{room['broach_session'].get("presence.json")['rooms'].inspect} should include id #{room['campfire_room_id']}");
#        $log.debug("check 2: #{room['broach_session'].get("room/#{room['campfire_room_id']}.json")['room']['users']} should include id #{user['campfire_id']}");

        # if ! room['broach_session'].get("presence.json")['rooms'].detect{ |x| x['id'] == room['campfire_room_id']} or
        #   ! room['broach_session'].get("room/#{room['campfire_room_id']}.json")['room']['users'].
        #   detect{ |x| x['id'] == user['campfire_id']} then

        $log.info( "attaching to room #{room['campfire_room_name']}, id #{room['campfire_room_id']}" )

        # This logs us in to the room.  We re-run it
        # periodically because we seem to fall out otherwise.
        #
        # Broach can't handle POST calls that return a flat 200,
        # which is a problem since the API does this repeatedly.
        #
        # FIXME:  Update the next line when that broach bug is
        # fixed

        # REST here is from the nap egg, which is what broach uses
#        $log.debug( "post: #{room['broach_session'].url_for("room/#{room['campfire_room_id']}/join")}, '', #{YAML::dump(room['broach_session'].headers_for(:post))}, #{YAML::dump(room['broach_session'].credentials)})" )
        REST.post(room['broach_session'].url_for("room/#{room['campfire_room_id']}/join"), '', room['broach_session'].headers_for(:post), room['broach_session'].credentials)
        # end

        # Also check membership, as that sort of thing seems to get
        # lost a fair bit
        fix_nicks( room, user )

        sleep 60
      end
    rescue SystemExit
      exit
    rescue Exception => e
      $log.info( "error in stay-attached thread: #{e.inspect}" )
    end
  end
end

#************************************************
# Campfire => Jabber Section
#************************************************
def campfire_to_jabber( room, user )
  th = Thread.new do
    if room['campfire_room'] == nil
      $log.error( "Room #{room['campfire_room_name']} doesn't seem to be working in Broach; perhaps the name is wrong?" )
      break
    end

    $log.debug( "In room thread for #{room['campfire_room_name']}" )

    url = URI.parse("http://#{user['campfire_token']}:x@streaming.campfirenow.com/room/#{room['campfire_room_id']}/live.json")

    $log.debug( "In room thread for #{room['campfire_room_name']}, streaming url: #{url}" )

    while true
      $log.debug( "In while in room thread #{Thread.current} for #{room['campfire_room_name']}" )

      sleep 5

      begin
        $log.debug( "In while in room thread for #{room['campfire_room_name']}, top of begin block" )

        # Stream messages from the campfire room
        Yajl::HttpStream.get(url) do |message|
          $log.debug( "In while in room thread #{Thread.current} for #{room['campfire_room_name']}, message: #{message.inspect}" )

          case message['type']
          when "TextMessage", "SoundMessage", "AdvertisementMessage",
            "AllowGuestsMessage", "DisallowGuestsMessage", "IdleMessage", "SystemMessage", 
            "TimestampMessage", "TopicChangeMessage", "UnidleMessage", "UnlockMessage"
            if message['body'] != nil
              $log.debug( "In while in room thread for #{room['campfire_room_name']}, sending message: #{message['body']}" )
              user_name=room['broach_session'].get("users/"+message['user_id'].to_s)['user']['name']
              send_to_jabber( room, user_name, message['body'] )
            end
          when "PasteMessage"
            user_name=room['broach_session'].get("users/"+message['user_id'].to_s)['user']['name']
            paste=message['body']
            if user.has_key?('paste_length') and user['paste_length'] != 'all'
              paste = paste.split("\n")[0,user['paste_length']].join("\n")
            end
            case user['paste_style']
            when "plain"
              $log.debug( "In while in room thread for #{room['campfire_room_name']}, sending plain paste" )
              send_to_jabber( room, user_name, paste )
            when "border"
              $log.debug( "In while in room thread for #{room['campfire_room_name']}, sending border paste" )
              send_to_jabber( room, user_name, 
                             "-- START PASTE -------------------------------\n" +
                             paste +
                             "\n--  END PASTE  -------------------------------"
                            )
            when "border_url"
              $log.debug( "In while in room thread for #{room['campfire_room_name']}, sending border_url paste" )
              send_to_jabber( room, user_name, 
                             "-- START PASTE: #{room['broach_session'].url_for("room/#{room['campfire_room_id']}/paste/#{message['id']}")} -------------------------------\n" +
              paste +
                "\n--  END PASTE  -------------------------------"
                            )
            else
              $log.fatal( "Invalid name paste_style #{user['paste_style']}; check the user config files." )
              exit 1
            end
          when "UploadMessage"
            user_name=room['broach_session'].get("users/"+message['user_id'].to_s)['user']['name']
            $log.debug( "In while in room thread for #{room['campfire_room_name']}, sending upload" )
            url ="room/#{room['campfire_room_id']}/messages/#{message['id']}/upload.json"
            upload_info = room['broach_session'].get(url)
            $log.debug( "upload info from #{url}: #{upload_info.inspect}" )

            send_to_jabber( room, user_name, "-- UPLOAD: #{upload_info['upload']['full_url']} -------------------------------" )
          when "KickMessage", "LeaveMessage", "JoinMessage", "EnterMessage"
            uname = room['broach_session'].get("users/#{message['user_id']}.json")['user']['id']
            fix_nicks( room, user )
          else
            $log.info( "In while in room thread for #{room['campfire_room_name']}, unknown message type; message: #{message.inspect}" )
          end
        end
      rescue SystemExit
        $log.info( "Exit received in room thread for #{room['campfire_room_name']}" )
        exit
      rescue Exception => e
        $log.info( "detached from room #{room['campfire_room_name']} via error: " )
        $log.info $!, $!.backtrace
      end
    end
  end
end

Daemons.run_proc('arson',
                :dir_mode => :script,
                :monitor => true,
                :log_output => true ) do

  $log.level = ArsonConfig::LogLevel

  Jabber::debug = ArsonConfig::JabberDebug

  $jabber_component = Jabber::Component::new(ArsonConfig::JabberComponentName, ArsonConfig::JabberComponentHost)
  $jabber_component.connect
  $jabber_component.auth(ArsonConfig::JabberComponentSecret)

  $jabber_component.add_message_callback do |message|
    $log.debug( "In add_message_callback: #{YAML::dump(message)}" )
    to = message.to.to_s
    from = message.from.to_s
    body = message.body.to_s
    $log.debug( "In add_message_callback: to: #{to}, from: #{from}, body: #{body}" )
#    #************************************************
#    # Jabber => Campfire Section
#    #************************************************
#    def muc_room_callback( room ) 
#      room[:jabber][:users]['virt_campfire'].add_message_callback do |message|
#        # Make sure it's directed to the master user
#        if to =~ Regexp.new("virt_campfire@campfire.localhost")
#          $log.debug( "muc full message: #{YAML::dump(message)}")
#
#          virtual_user = false
#
#          # make sure it didn't come from any of our virtual users
#          room[:jabber][:users].keys.each do |uname|
#            $log.debug( "uname check: #{name_to_jabber_nick(uname, room)} vs --#{message.from.to_s.inspect}--" )
#
#            if Regexp.new("@conference.localhost/#{name_to_jabber_nick(uname, room)}$").match( message.from.to_s )
#              $log.debug( "uname check failed" )
#              # It's from one of our virtual users; no thank you.
#              virtual_user = true
#            end
#          end
#
#          # Basic OK checks on the message
#          if message.from != '' and message.body != '' and not virtual_user and not
#            # make sure it isn't a delayed/history message
#            message.elements.find { |elem| elem.class.to_s == 'Jabber::Delay::XDelay' } and
#            send_to_campfire( room, message.body )
#          end
#        end
#      end
#
#      #   room[:jabber][:users]['virt_campfire'].on_message do |time, from, body| 
#      #     $log.debug( "muc message: #{time.inspect}, #{from.inspect}, #{body.inspect}" )
#      #     if from != '' and body != '' and not
#      #         room[:jabber][:users].keys.find { |uname| uname =~ Regexp.new("@campfire.localhost/#{uname}$") }
#      #         print "FIXME\n"
#      #       #send_to_campfire( room, body )
#      #     end
#      #   end
#    end
  end

  # Jabber Presence Handling
  $jabber_component.add_presence_callback do |pres|
    user_found=false
    from = pres.from.to_s
    to = pres.to.to_s

    # Here we walk through each of the users and see if this is a
    # message for one of them, and handle it appropriately (which
    # basically means either setting up handling for the campfire
    # room that goes with the jabber room they asked for, or doing
    # nothing.)
    $users.each do |user|
      if Regexp.new("^#{user['jabber_id']}/").match( from )
        user_found = true

        # We've found the user; now find the room
        user['rooms'].each do |room|
          if room['campfire_room_name'].casecmp( to.gsub(/\@.*/, '') ) == 0
            # We've matched the room; do we already have it?
            if ! room.has_key?('campfire_room')
              $log.debug( "Presence received for room #{to}, setting it up now." )
              # We don't; set it up
              Broach.settings = {
                'account' => 'engineyard',
                'token'   => user['campfire_token'],
                'use_ssl' => true
              }

              # Now that broach is setup, get the user's campfire_id
              # if we don't already have it.
              if ! user.has_key?('campfire_id')
                user['campfire_id'] = Broach.session.get("users/me.json")['user']['id']
              end

              room['jabber_users'] = Hash.new

              room['campfire_room'] = Broach::Room.find_by_name( room['campfire_room_name'] )

              room['campfire_room_id'] = room['campfire_room'].id

              room['broach_session'] = Broach.session

              room['user_jid'] = from

              room['room_jid'] = to

              fix_nicks( room, user )

              # Let the user know they're in
              send_presence( room['room_jid'], room['user_jid'], nil, true, 'member', 'participant', nil, [ '110', '210' ] )

              #muc_room_callback( room )

              stay_in_campfire_room( room, user )

              campfire_to_jabber( room, user )
            else
              $log.debug( "Presence received for room #{to}, but it needs no setup." )
            end
          else
            print "No room match\n"
          end
        end
      end
    end

    if ! user_found
        presence = Jabber::Presence.new.set_from(to.gsub(/\/[^\/]*$/, '')).set_to(from).set_type(:error)
        print "presence: #{YAML::dump(presence)}\n"
        presence.add_element( Jabber::MUC::XMUC.new() )
        print "presence: #{YAML::dump(presence)}\n"
        presence.add_element( Jabber::ErrorResponse.new( "not-authorized", "The campfire server has never heard of you." ).set_type(:auth))
        print "presence: #{YAML::dump(presence)}\n"
        $jabber_component.send(presence)
    end
  end

  print "stopping\n"

  sleep 10000000

  Thread.stop

##   Broach.settings = {
##     'account' => 'engineyard',
##     'token'   => campfire_token,
##     'use_ssl' => true
##   }
## 
##   my_campfire_id = Broach.session.get("users/me.json")['user']['id']
## 
##   # setup
##   $rooms.each do |room|
##     print "\n\n***************ROOOOM\n\n"
##     room[:jabber][:users] = Hash.new
## 
##     room[:campfire_room] = Broach::Room.find_by_name( room[:campfire][:room_name] )
## 
##     fix_nicks( room )
## 
##     muc_room_callback( room )
## 
##     ##       jabber_muc = Jabber::Simple.new(room[:jabber][:user], room[:jabber][:pass])
##     ##       # If you don't wait, jabber might not notice you
##     ##       sleep 5;
##     ##       im.add(room[:jabber][:deliver_to]);
##     ## 
##     ##       room[:im] = im
##     ## 
##     ##       room[:last_message] = 0
##     ## 
##     ##       room[:check_counter] = 999999
##   end
## 
##   #*************************
##   # This is the "make sure camfire knows we're here" section.
##   #*************************
##   th = Thread.new do
##     begin
##       $rooms.each do |room|
##         campfire_room = room[:campfire_room]
##         campfire_room_id = room[:campfire_room].id
## 
##         $log.debug("checking room")
##         $log.debug("check 1: #{Broach.session.get("presence.json")['rooms'].inspect} should include id #{campfire_room_id}");
##         $log.debug("check 2: #{Broach.session.get("room/#{campfire_room_id}.json")['room']['users']} should include id #{my_campfire_id}");
##         #          if room[:check_counter] > 10 or
##         #            ! Broach.session.get("presence.json")['rooms'].detect{ |x| x['id'] == campfire_room_id} or
##         #            ! Broach.session.get("room/#{campfire_room_id}.json")['room']['users'].detect{ |x| x['id'] == my_campfire_id} then
## 
##         $log.info( "attaching to room #{room[:campfire][:room_name]}, id #{campfire_room_id}" )
## 
##         # This logs us in to the room.  We re-run it
##         # periodically because we seem to fall out otherwise.
##         #
##         # Broach can't handle POST calls that return a flat 200,
##         # which is a problem since the API does this repeatedly.
##         #
##         # FIXME:  Update the next line when that broach bug is
##         # fixed
##         REST.post(Broach.session.url_for("room/#{campfire_room_id}/join"), '', Broach.session.headers_for(:post), Broach.session.credentials)
## 
##         #            room[:check_counter] = 0
##         #          end
##       end
##     rescue SystemExit
##       exit
##     rescue Exception => e
##       $log.info( "error in stay-attached thread: #{e.inspect}" )
##     end
## 
## 
##     sleep 60
##   end
##   #*************************
##   # END "make sure camfire knows we're here" section.
##   #*************************
## 
##   #************************************************
##   # Campfire => Jabber Section
##   #************************************************
##   $rooms.each do |room|
##     th = Thread.new do
##       if room[:campfire_room] == nil
##         $log.error( "Room #{room[:campfire][:room_name]} doesn't seem to be working in Broach; perhaps the name is wrong?" )
##         break
##       end
## 
##       $log.debug( "In room thread for #{room[:campfire][:room_name]}" )
## 
##       campfire_room = room[:campfire_room]
##       campfire_room_id = room[:campfire_room].id
## 
##       url = URI.parse("http://#{campfire_token}:x@streaming.campfirenow.com/room/#{campfire_room_id}/live.json")
## 
##       while true
##         begin
##           $log.debug( "In while in room thread for #{room[:campfire][:room_name]}" )
## 
##           # Stream messages from the campfire room
##           Yajl::HttpStream.get(url) do |message|
## ## {"room_id"=>343561, "created_at"=>"2011/02/12 04:30:00 +0000", "body"=>nil, "id"=>311411718, "type"=>"TimestampMessage", "user_id"=>nil}
## ## {"room_id"=>343561, "created_at"=>"2011/02/12 04:34:02 +0000", "body"=>"cf test #3", "id"=>311411719, "type"=>"TextMessage", "user_id"=>733667}
## ##   <type>#{TextMessage || PasteMessage || SoundMessage || AdvertisementMessage ||
## ##             AllowGuestsMessage || DisallowGuestsMessage || IdleMessage || KickMessage ||
## ##                         LeaveMessage || SystemMessage || TimestampMessage || TopicChangeMessage ||
## ##                                   UnidleMessage || UnlockMessage || UploadMessage}</type>
## ##             </message>
##             $log.debug( "In while in room thread for #{room[:campfire][:room_name]}, message: #{message.inspect}" )
##             case message['type']
##             when "TextMessage", "PasteMessage", "SoundMessage", "AdvertisementMessage",
##               "AllowGuestsMessage", "DisallowGuestsMessage", "IdleMessage", "SystemMessage", 
##               "TimestampMessage", "TopicChangeMessage", "UnidleMessage", "UnlockMessage", "UploadMessage"
##               if message['body'] != nil
##                 $log.debug( "In while in room thread for #{room[:campfire][:room_name]}, sending message: #{message['body']}" )
##                 user_name=Broach.session.get("users/"+message['user_id'].to_s)['user']['name']
##                 send_to_jabber( room, user_name, message['body'] )
##               end
##             when "KickMessage", "LeaveMessage", "JoinMessage", "EnterMessage"
##               fix_nicks( room )
##             else
##               $log.info( "In while in room thread for #{room[:campfire][:room_name]}, unknown message type; message: #{message.inspect}" )
##             end
##           end
##         rescue SystemExit
##           $log.info( "Exit received in room thread for #{room[:campfire][:room_name]}" )
##           exit
##         rescue Exception => e
##           $log.info( "detached from room #{room[:campfire][:room_name]} via error: #{e.inspect}" )
##         end
##       end
## 
##     end
##   end
end


Thread.stop
