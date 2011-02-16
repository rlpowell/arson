module ArsonConfig
  # BEGIN CHANGE SECTION

  # FIXME: describe
  #LogLevel = Logger::INFO
  LogLevel = Logger::DEBUG

  # FIXME: describe
  JabberDebug = true

  # FIXME: describe
  JabberComponentName = 'campfire.localhost'
  JabberComponentHost = 'localhost'
  JabberComponentSecret = 'campfirepass'

  # Any given arson server only supports one campfire domain.
  CampfireDomain = 'engineyard.campfirenow.com'
  CampfireUseSSL = true

  # FIXME: describe
  Configs = [
    "/home/rpowell/.arsonrc",
  ]

  Rooms = [
    {
      :campfire_room_name => "Support",
      :jabber_room_name => "Support",
    },
    {
      :campfire_room_name => "Testing",
      :jabber_room_name => "Testing",
    },
  ]

  #Users = [
  #  {
  #
  #  Idea: split up the program into two sections, so that the server can run one Campfire -> Jabber 
  #  with one user's creds and logged into all the rooms, and each user can run their own
  #  Jabber -> Campfire for themselves.
  #
  #    # This is your campfire API token; see
  #    #
  #    # http://developer.37signals.com/campfire/
  #    :campfire_token => '98a9607eadfd2fe3173e9cb032b1e5dacd1dce15',
  #    # FIXME: describe
  #    :jabber_name => 'wibble',
  #  }
  #]

  ## Your campfire room/jabber information
  ##
  ## FIXME: describe
  #$rooms = [
  #  # Each room has a jabber segment and a campfire segment
  #  {
  #  # The campfire information
  #  :campfire => {
  #  # The campfire room to listen in
  #  :room_name => "Support",
  #  # The campfire domain
  #  :domain => 'engineyard.campfirenow.com',
  #  # Use ssl?
  #  :ssl => true,
  #  # Any message from a campfire user with this name is
  #  # ignored. Setting this to your own Campfire name is
  #  # important, because otherwise you'll get your own messages
  #  # coming back to you.
  #  :self_name => "Robin Powell",
  #},
  ## The jabber information
  #:jabber => {
  #  # The jabber user to login in as.  Every message from the
  #  # campfire room is sent from this jabber user,
  #  :user => 'ey-cf-support@localhost',
  #  :pass => 'password',
  #  # The jabber user to send the messages to.
  #  :deliver_to => 'rpowell@localhost',
  #},
  #},
  ###     # Other rooms, more compact
  ###     {
  ###       :jabber => {:user => 'ey-cf-sam@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
  ###       :campfire => {:room_name => "SAM", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
  ###     },
  ###     {
  ###       :jabber => {:user => 'ey-cf-sysadmin@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
  ###       :campfire => {:room_name => "Sysadmin", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
  ###     },
  ### #    {
  ### #      :jabber => {:user => 'ey-cf-spam@localhost',:pass => 'password', :deliver_to => 'rpowell@localhost' },
  ### #      :campfire => {:room_name => "Spam", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Robin Powell" }
  ### #    },
  ###     {
  ###       :jabber => {:room_name => 'COMey-cf-testing@conference.localhost'},
  ###       :campfire => {:room_name => "Testing", :domain => 'engineyard.campfirenow.com', :ssl => true, :self_name => "Wibble" }
  ###     },
  #]
  #
  ## END CHANGE SECTION
  #
  #
end
