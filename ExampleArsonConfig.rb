
# This is the master config for arson.  It's regular Ruby code.

module ArsonConfig
  # Sets the level of log messages to output; leave this alone
  # unless you're debugging, since the log messages are pretty
  # infrequent at INFO.
  LogLevel = Logger::INFO
  #LogLevel = Logger::DEBUG

  # The directory to store the log files.  If started with the -t
  #  option, ouptuts to STDERR.  Otherwise, everything is put in a
  # file named arson.output in this directory, except exceptions,
  # which are put in arson.log.
  LogDir = "/home/rpowell/arson/"

  # Set to an email address if you want want be emailed on severe
  # errors
  SystemEmail = nil

  # Set to true to see debugging information for all Jabber
  # stanzas.
  JabberDebug = false
  #JabberDebug = true

  # This is the jabber commonent information that you've set up on
  # your jabber server; see the README file for details.
  JabberComponentName = 'campfire.localhost'
  JabberComponentHost = 'localhost'
  JabberComponentSecret = '[COMPONENT PASSWORD]'

  # Any given arson server only supports one campfire domain; this
  # is the information for that domain.
  CampfireDomain = 'engineyard.campfirenow.com'
  CampfireUseSSL = true

  # This is a list of user config files to import.  These are YAML
  # files; see example_arsonrc for details.
  Configs = [
    "/home/[user]/.arsonrc",
  ]
end
