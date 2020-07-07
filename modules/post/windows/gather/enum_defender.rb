##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Gather Defender Data Enumeration",
      'Description'          => %q{
        This module will collect data related to Windows Defender.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               =>
        [
          'bwatters-r7'
        ]
    ))
  end

  def convert_windows_timestamp(timestamp)
    # windows bases timestamps off of Jan 1, 1601
    recentered_timestamp = timestamp - 116444736000000000
    #remove fractions of a second because who cares.....
    unix_timestamp = recentered_timestamp/10000000
    return unix_timestamp
  end
  def check_reg_keys
    reg_key = 'HKLM\SOFTWARE\Microsoft\Windows Defender'
    keys = registry_enumvals(reg_key)
    keys.each do |key|
      valdata = registry_getvaldata(reg_key, key, REGISTRY_VIEW_NATIVE)
      if key.include?('ime')
        print_status("#{key} = #{Time.at(convert_windows_timestamp(valdata.unpack("Q")[0]))}")
      else
        print_status("#{key} = #{valdata}")
      end
    end
  end
  def check_service
    scm_reply = cmd_exec('sc query WinDefend')
    vprint_status("sc query response: \n#{scm_reply}")
  end
  def get_process_by_name(search_name)
    proclist = client.sys.process.processes
    begin
      procs = client.sys.process.processes
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Unable to retrieve process list")
      return nil
    end
    procs.each do |p|
      process_name = p['name']
      return p if process_name == search_name
    end
    return nil
  end
  def run
    check_service
    check_reg_keys
    defender_process = 'MsMpEng.exe'
    proc = get_process_by_name(defender_process)
    if proc.nil?
      print_status("No Defender user process found")
    else
      print_status("Defender user process present")
    end
  end
end
