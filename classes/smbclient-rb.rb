# SMBClient Wrapper Class

class RubySmbClient
  require 'pty'
  require 'expect'
  require 'tempfile'

  def initialize(host='127.0.01', port=445, share='C$', user='Administrator', pass=nil, domain=nil, hashpass=false)
    @host     = host
    @port     = port.to_i
    @share    = share
    @user     = user
    @pass     = pass
    @domain   = domain
    @hashpass = hashpass
    smbclient = commandz('which smbclient')[0]
    if smbclient.nil? or smbclient == ''
      puts
      @smbclient = nil
      raise("Fatal Error: Can not find SMBCLIENT!\n\n")
      exit(666);
    else
      @smbclient = smbclient.chomp
    end
  end

  # Return an array of the connection info
  def client_creds
    return @smbclient, @host, @port, @share, @user, @pass, @domain
  end

  # Check if we can connect with credentials
  # Returns true on success, false otherwise
  # Sets $os var based on response for recall later
  def can_we_connect?
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      connected = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'pwd' > #{file.path} 2>&1")
    else
      connected = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'pwd' > #{file.path} 2>&1")
    end
    res = File.open(file.path).readlines
    if res.join("\n") =~ /Domain=(.+)\sOS/
      $domain=$1.sub(/^\[/, '').sub(/\]$/, '')
    end
    if res.join("\n") =~ /Server=(.+)\s+/
      server=$1.sub(/^\[/, '').sub(/\]$/, '')
    end
    if res.join("\n") =~ /Domain=.+\sOS=(.+)\sServer=/
      $os=$1.sub(/^\[/, '').sub(/\]$/, '') + ' (' + server + ')'
    end
    file.unlink
    if connected
      return true
    else
      return false
    end
  end

  # Check OS of target
  def os_discovery
    file = Tempfile.new('ruby_smbclient')
    success = system("#{@smbclient} -L #{@host} -p #{@port} -N > #{file.path} 2>&1")
    if success
      res = File.open(file.path).readlines
      if res.join("\n") =~ /Domain=(.+)\sOS/
        domain=$1.sub(/^\[/, '').sub(/\]$/, '')
      end
      if res.join("\n") =~ /Server=(.+)\s+/
        server=$1.sub(/^\[/, '').sub(/\]$/, '')
      end
      if res.join("\n") =~ /Domain=.+\sOS=(.+)\sServer=/
        os=$1.sub(/^\[/, '').sub(/\]$/, '') + ' (' + server + ')'
      end
      return true, os, domain
    else
      return false, nil, nil
    end
  end

  # Performs Anonymous SMB Connection
  # List Shares on Box with NULL creds if possible
  # We cam also use this method for our OS Version Scanning
  def list_shares_anonymous
    file = Tempfile.new('ruby_smbclient')
    success = system("#{@smbclient} -L #{@host} -p #{@port} -N > #{file.path} 2>&1")
    if success
      res = File.open(file.path).readlines
      if res.join("\n") =~ /Domain=(.+)\sOS/
        $domain=$1.sub(/^\[/, '').sub(/\]$/, '')
      end
      if res.join("\n") =~ /Server=(.+)\s+/
        server=$1.sub(/^\[/, '').sub(/\]$/, '')
      end
      if res.join("\n") =~ /Domain=.+\sOS=(.+)\sServer=/
        $os=$1.sub(/^\[/, '').sub(/\]$/, '') + ' (' + server + ')'
      end
      if res.join("\n") =~ /Error returning browse list: (.+)/i
        file.unlink
        return false, "Unable to enumerate shares anonymously: #{$1}"
      else
        if res =~ /Domain=\[.+\]\s+Sharename\s+Type\s+Comment\s+[-]{1,}\s+[-]{1,}\s+[-]{1,}\s+(.+)\s+Domain/m and not rez =~ /Error returning browse list: .+/i
          results=$1
          shares = [["Sharename", "Type", "Comment"]]
          results.split("\n").each do |share|
            row = share.strip.chomp.split(' ')
            shares << [ row[0], row[1], row[2..-1].join(' ') ]
          end
          file.unlink
          table = t.to_table(:first_row_is_head => true)
          return true, table.to_s
        else
          return false, "Unable to enumerate shares anonymously!"
        end
      end
    else
      return false, "Unable to enumerate shares anonymously!" 
    end
  end

  # List Available Shares w/Credentials
  # Requires password prompt so useing PTY to leverage .expect
  # Allows us to password password at right moment....got anything better?
  def list_shares_credentialed
    file = Tempfile.new('ruby_smbclient')
    begin
      if @hashpass
        # We use PTY so we can leverage the built-in expect function to wait and enter password at proper moment
        # The output is written to tempfile thanks to our redirection in intial spawned command
        # Read results from file after and do what you need....
        PTY.spawn("#{@smbclient} -L #{@host} -p #{@port} --pw-nt-hash -U #{@user} > #{file.path} 2>&1") do |read,write,pid|
          read.expect(/^Enter Administrator's password:/i, 10) do |output|
            write.puts(@pass)
            shares = read.expect(/Domain=\[.+\]\s+Sharename\s+Type\s+Comment\s+[-]{1,}\s+[-]{1,}\s+[-]{1,}\s+(.+)\s+Domain/m)
          end
        end
      else
        PTY.spawn("#{@smbclient} -L #{@host} -p #{@port} -U #{@user} > #{file.path} 2>&1")  do |read,write,pid|
          read.expect(/^Enter Administrator's password:/i, 10) do
            write.puts(@pass)
            shares = read.expect(/Domain=\[.+\]\s+Sharename\s+Type\s+Comment\s+[-]{1,}\s+[-]{1,}\s+[-]{1,}\s+(.+)\s+Domain/m)
          end
        end
      end
    rescue Errno::EIO
      # We will generate an error due to our piped redirection to tempfile in OS cmd
      # This simply catches it so we can continue after results are read in.....
    end
    output = File.open(file.path).readlines
    output = output.uniq
    file.unlink
    return output
  end

  # Make a new directory on remote system
  # Pass in directory to change to, otherwise uses connected directory
  def smb_mkdir(dirname, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'mkdir #{dirname}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'mkdir #{dirname}'#{dir} > #{file.path} 2>&1")
    end
    file.unlink
    if success
      return true
    else
      return false
    end
  end

  # Remove a file on remote system
  # Can actually accept a mask (*.txt), but trying to keep to single file for simplified use (ubers use how you like....)
  # Pass in directory to change to, otherwise uses connected directory to look in for target file/mask
  def smb_rm(filename, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'rm #{filename}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'rm #{filename}'#{dir} > #{file.path} 2>&1")
    end
    file.unlink
    if success
      return true
    else
      return false
    end
  end

  # Remove a directory on remote system
  # Pass in directory to change to, otherwise uses connected directory to look in for target
  def smb_rmdir(dirname, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'rmdir #{dirname}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'rmdir #{dirname}'#{dir} > #{file.path} 2>&1")
    end
    file.unlink
    if success
      return true
    else
      return false
    end
  end

  # Run an smbclient command (-c) of your choosing
  # Returns results from output as response array (line by line)
  def smb_cmd(cmd, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c '#{cmd}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c '#{cmd}'#{dir} > #{file.path} 2>&1")
    end
    if success
      output = File.open(file.path).readlines
    else
      output=nil
    end
    file.unlink
    return output
  end

  # Rename Files on Remote System
  # If it is not in current directory you can pass in the directory to use (rdir)
  def smb_file_rename(rfile, new_name, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'rename #{rfile} #{new_name}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'rename #{rfile} #{new_name}'#{dir} > #{file.path} 2>&1")
    end
    file.unlink
    if success
      return true
    else
      return false
    end
  end

  # Download a file over SMB
  # Pass in path to destination file and where to write locally
  # Returns True on success, False otherwise
  def smb_download(rfile, lfile, rdir=nil)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'get #{rfile} #{lfile}'#{dir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'get #{rfile} #{lfile}'#{dir} > #{file.path} 2>&1")
    end
    output=File.open(file.path).readlines
    file.unlink
    if success
      return true 
    else
      puts "Problem Downloading #{rfile}!"
      c=0
      output.each do |l|
        puts "\t=> #{l}" unless c.to_i == 0
        c+=1
      end
      return false
    end
  end

  # Download ALL files from directory
  # If it is not in current directory you can pass in the directory to use (rdir)
  # prompt is default by default, set confirmation true to prompt user confirmation before each file download
  def download_dir(directory, rdir=nil, confirmation=false)
    if rdir.nil?
      dir=''
    else
      dir=' -D ' + rdir
    end
    if confirmation
      prompt='prompt '
    else
      prompt=''
    end
    file = Tempfile.new('ruby_smbclient')
    begin
      if @hashpass
        # We use PTY so we can leverage the built-in expect function to wait and enter password at proper moment
        # The output is written to tempfile thanks to our redirection in intial spawned command
        # Read results from file after and do what you need....
        PTY.spawn("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} --pw-nt-hash -U #{@user} #{@pass}#{dir} > #{file.path} 2>&1") do |read,write,pid|
          read.expect(/^smb:.*\\>/i, 5) { |output| 
            write.puts("tarmode")
            read.expect(/^smb:.*\\>/i, 5) { |output| 
              write.puts("recurse") 
              read.expect(/^smb:.*\\>/i, 5) { |output| 
                write.puts("prompt") 
                read.expect(/^smb:.*\\>/i, 5) { |output| 
                  write.puts("mget #{directory}")
                  read.expect(/^smb:.*\\>/i, 5)
                }
              } unless confirmation
            }
          }
        end
      else
        PTY.spawn("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass}#{dir} > #{file.path} 2>&1")  do |read,write,pid|
          read.expect(/^smb:.*\\>/i, 5) { |output| 
            write.puts("tarmode")
            read.expect(/^smb:.*\\>/i, 5) { |output| 
              write.puts("recurse") 
              read.expect(/^smb:.*\\>/i, 5) { |output| 
                write.puts("prompt") 
                read.expect(/^smb:.*\\>/i, 5) { |output| 
                  write.puts("mget #{directory}")
                  read.expect(/^smb:.*\\>/i, 5)
                }
              } unless confirmation
            }
          }
        end
      end
    rescue Errno::EIO
      # We will generate an error due to our piped redirection to tempfile in OS cmd
      # This simply catches it so we can continue after results are read in.....
    end
    output = File.open(file.path).readlines
    output = output.uniq
    file.unlink
    return output
  end

  # Upload a file over SMB
  # Pass in local file and path on destination where to write
  # Returns True on success, False otherwise
  def smb_upload(lfile, rdir)
    file = Tempfile.new('ruby_smbclient')
    if @hashpass
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass} -c 'put #{lfile}' -D #{rdir} > #{file.path} 2>&1")
    else
      success = system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass} -c 'put #{lfile}' -D #{rdir} > #{file.path} 2>&1")
    end
    output=File.open(file.path).readlines
    file.unlink
    if success
      return true
    else
      puts "Problem Uploading #{lfile}!"
      c=0
      output.each do |l|
        puts "\t=> #{l}" unless c.to_i == 0 or l == ''
        c+=1
      end
      return false
    end
  end

  # Let the user have an interactive SMB Shell
  # This is the default smbclient smb shell....
  def smb_shell
    if @hashpass
      system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} --pw-nt-hash #{@pass}")
    else
      system("#{@smbclient} \\\\\\\\#{@host}\\\\#{@share} -p #{@port} -U #{@user} #{@pass}")
    end
  end
end
