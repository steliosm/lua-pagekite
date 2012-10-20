#!/usr/bin/lua

--
-- Pagekite back-end client in Lua
-- by Stelios Mersinas (steliosm@steliosm.net)
-- v0.5
--
--[[
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]
--

-- 
-- Changelog:
-- 
-- 0.5
-- Code clean up: Protocol handlers return the whole response frame
-- Responds to PING requests from the server.
--
-- 0.4
-- Added support for POST requests
-- Changed the frame parsing mechanism
--
-- 0.3.1
-- Closes the socket objects created in the HTTP handler
--
-- 0.3
-- Supports tunnel status check using PING headers.
--

-- Load the needed modules
require "socket"
require "os"
require "math"

-- load the SHA1 encryption library
dofile "lib/shalib.lua"

--
-- Read the config file
--
dofile "config.cfg"

-- Defines go here
app_version = "0.5"

--
-- Functions Part
--

function string.trim(str)
  return (string.gsub(str, "^%s*(.-)%s*$", "%1"))
end


function string.explode(str, sep)
  -- Split a string based on sep value.
  -- Return a table back
  local pos, t = 1, {}
  if #sep == 0 or #str == 0 then return end
  for s, e in function() return string.find(str, sep, pos) end do
    table.insert(t, string.trim(string.sub(str, pos, s-1)))
    pos = e+1
  end
  table.insert(t, string.trim(string.sub(str, pos)))
  return t
end


function FrameToTable(str)
  local t = {}
  local function helper(line) table.insert(t, line .. "\r\n") return "" end
  helper((str:gsub("(.-)\r?\n", helper)))
  return t
end


function sleep (my_sec)
  -- A function to make Lua sleep for a bit :-)
  -- It's an ugly hack actually.
  os.execute("sleep " .. tonumber(my_sec))
end


function ConnectToServer (my_server, my_port)
  -- Create a socket and connect to server/port given.
  -- In case of a connection problem, conn will be nil and status will hold the error message
  local conn, status = socket.connect (my_server, my_port)

  -- Check weather we got a connection to set the timeout option
  if conn then
    -- Set a socket timeout value. This will allow us to skip blobking for ever on socket:receive()
    conn:settimeout (30)
  end
  
  -- Return the socket object
  return conn, status
end


function PingServer (fe_socket)
  --
  -- Do a PING request to the server to check if the tunnel is still active
  -- The server should response with a NOOP header.
  -- In case the connection is down, then the socket:receive() will timeout
  -- and a new tunnel will be crated.
  --

  if debug then print ( os.date("%c"), "[PingServer] Ping?") end
  local ping = false

  -- Build the Ping request frame
  local my_chunk = "NOOP: 1\r\nPING: 1\r\n\r\n!"
  local my_chunk_length = string.len(my_chunk)
  local my_frame = string.format ("%x", my_chunk_length) .. "\r\n" .. my_chunk

  -- Send the Ping request to the server
  fe_socket:send ( my_frame )
  
  -- Check for the reply
  frame_header, status, partial = fe_socket:receive("*l")

  if frame_header ~= nil then
    -- Socket didn't timeout, the connection seems to be alive.
    -- Read the rest of the frame data and look for a NOOP reply
    local frame_size = tonumber (frame_header, 16)
    local frame_data, status, partial = fe_socket:receive (frame_size)

    -- Check for the NOOP header
    if string.find (frame_data, "NOOP") then
      if debug then print (os.date("%c"), "[PingServer] Pong!") end
      ping = true
    end
  else
    ping = false
  end

  -- Return the results
  return ping
end


function PhaseOne ()
  --
  -- Make a connection to PageKite server and send a challenge request.
  -- This is the first phase of the authecation handshakng procedure.
  --

  -- Define the variable to hold the server's response
  local my_challenge_string, my_session_id = ""

  -- Generate a random string using the math.random() functionstring.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 )
  -- and cut a 36-bytes long string for the BSalt field and a 8 byte long string for the salt.
  math.randomseed ( os.time() )
  local my_random_bsalt =  string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 36)
  local my_random_salt = string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 8)

  -- Sign the data string (Sig) using the shared secret contained in the .config file
  local my_data = string.format ("http:%s:%s", pk_site, my_random_bsalt)
  --local my_signed_string = string.sub("87654321" .. sha1(pk_server_token .. my_data .. ":87654321"), 1, 36)
  local my_signed_string = string.sub(my_random_salt .. sha1(pk_server_token .. my_data .. ":" .. my_random_salt), 1, 36)

  -- Create the Phase-One authentication request
  local my_request = "CONNECT PageKite:1 HTTP/1.0\r\n" .. "X-PageKite-Version: 0.3.21\r\n" ..
  string.format ( "X-PageKite: http:%s:%s::%s", pk_site, my_random_bsalt, my_signed_string ) .. "\r\n\r\n"

  -- Make a connection to the Front-end server
  local remote_conn, error = ConnectToServer (pk_server, pk_server_port)

  -- Check if the connection was sucessful
  if remote_conn then
    -- We have a connection, send the authentication string
    remote_conn:send ( my_request )

    -- Read the response for the server. Look for the challenge header
    while true do
      local data, status, partial = remote_conn:receive ("*l")
      -- Check if the remote port is closed
      if status == "closed" then break end

      -- Check for the challenge header
      if data ~= "" then
        header = string.explode(data, ":")

        -- Look for the Challenge request
        if header[1] == "X-PageKite-SignThis" then
          -- Challenge string found
          my_challenge_string = string.sub(data,22)
        end

        -- Look for the Session ID
        if header[1] == "X-PageKite-SessionID" then
          -- Session ID header found
          my_session_id = string.sub(data,23)
        end
      end
    end

    -- Close the socket - should already be closed by the server
    remote_conn:close()

    -- Return the values back
    return my_challenge_string, my_session_id

  else
    -- Error connecting to remote server. Return nil and the error message
    return nil, error
  end

end


function PhaseTwo (my_challenge_header, my_session_id)
  --
  -- Reply to the challenge request and setup the tunnel
  --

  -- Create challenge reply
  local my_random_salt = string.sub ( string.sub ( math.random(), 3 ) .. string.sub ( math.random(), 3 ), 1, 8)
  local my_challenge_reply = my_random_salt .. sha1 (pk_server_token .. my_challenge_header .. my_random_salt)

  -- Build the response
  local my_challenge_response = "CONNECT PageKite:1 HTTP/1.0\r\n" .. "X-PageKite-Version: 0.3.21\r\n" ..
  string.format ("X-PageKite-Replace: %s", my_session_id) .. "\r\n" ..
  string.format ("X-PageKite: %s:%s", my_challenge_header, string.sub(my_challenge_reply,1,36)) .. "\r\n\r\n"

  -- Connect to the server and send the reply back
  local remote_conn, error = ConnectToServer (pk_server, pk_server_port)

  -- Check if got connected and send the reply back
  if remote_conn then
    -- Send the response back
    remote_conn:send ( my_challenge_response )

    -- Read the response for the server. Look for the OK header
    while true do
      data, status, partial = remote_conn:receive ("*l")
      if status == "closed" then break end
      if data ~= "" then
        header = string.explode(data, ":")
      end
      if header[1] == "X-PageKite-OK" then
        -- OK header found, set a flag
        ok_flag = 1
      end
      if data == "" and ok_flag == 1 then
        -- Final line, exit the loop
        break
      end
    end

    -- Tunnel is configured, return the socket object.
    return remote_conn
  else
    -- Problem connecting to server and setting up the tunnel.
    -- Send a nil value and the error message.
    return nil, error
  end
end


function PING_handler ( )
  --
  -- Send a PING reply to the Front End
  --
  
  -- Print a debug message
  if debug then print (os.date("%c"), "[PING Handler] Sending PING reply") end
  
  -- Build the Ping frame request
  local ping_chunk = "NOOP: 1\r\n\r\n!"
  local ping_chunk_length = string.len(ping_chunk)
  local ping_frame = string.format ("%x", ping_chunk_length) .. "\r\n" .. ping_chunk

  -- Return the frame reply back
  return ping_frame
end


function HTTP_handler ( my_frame_table )
  --
  -- Makes HTTP requests to the web server specified in the config file
  -- Returns a reply frame containing the server's reply and the EOF for the session
  -- 

  local http_reply, http_reply_frame, http_conn, http_frame, http_chunk, http_chunk_length
  local session_id, eof_frame, eof_chunk, eof_chunk_length
  
  -- Store the SID located in the first row of the request table
  frame_header = string.explode(my_frame_table[1], ":")
  session_id = frame_header[2]
    
  -- Format the frame table into a HTTP request string
  for i=1,7 do
    -- Remove the first row from the table seven times
    table.remove(my_frame_table,1)
  end
                  
  -- Concatenate the rest of the table into a string
  http_request = table.concat(my_frame_table)

  -- Open a connection to the server
  local remote_conn, error = ConnectToServer (proxy_web, proxy_web_port)
  if debug then print (os.date("%c"), "[HTTP Handler] Connecting to server " .. proxy_web .. ":" .. proxy_web_port) end

  -- Check if we got connected to the web server
  if remote_conn then
    -- We have a connection, send the request!
    if debug then print (os.date("%c"), "[HTTP Handler] Sending HTTP request") end
    remote_conn:send( http_request )

    -- Get the reply back from the web server
    if debug then print (os.date("%c"), "[HTTP Handler] Receiving HTTP reply") end
    http_reply = remote_conn:receive("*a")

    -- Close the socket object
    remote_conn:close()
  else
    -- Problem connecting, send error message back
    -- ToDo: Send a proper message back!
    http_reply = "ERROR!"
  end
  
  -- Create the HTTP reply frame
  http_chunk = "SID: " .. session_id .. "\r\n" .. "\r\n" .. http_reply
  http_chunk_length = string.len (http_chunk)
  http_frame = string.format ("%x", http_chunk_length) .. "\r\n" .. http_chunk

  -- Create the EOF frame  
  eof_chunk = "SID: " .. session_id .. "\r\n" .. "EOF: RW" .. "\r\n\r\n"
  eof_chunk_length = string.len (eof_chunk)
  eof_frame = string.format ("%x", eof_chunk_length) .. "\r\n" .. eof_chunk
   
  -- Combine the two frames
  http_reply_frame = http_frame .. eof_frame
  
  -- Return the frame reply back
  return http_reply_frame
end


function RequestHandler ( my_frame_table )
  --
  -- Parse the frame table and send a reply frame back
  -- Find out the request type and call the apropriate protocol handler
  --
  
  local protocol_response

  -- Check the type of the Request and call the apropriate handler.
  if string.find (my_frame_table[2], "Proto: http") then
  
    -- It's an HTTP request. Call the HTTP Handler function
    if debug then print (os.date("%c"), "[Request Handler] Received HTTP request. Calling HTTP Handler") end
    protocol_response = HTTP_handler ( my_frame_table )
  
  -- It's not an HTTP request, check what frame it is and procces it or discard it.
  elseif string.find (my_frame_table[1], "NOOP") then
  
     -- Look for a PING request from the front end
     if string.find (my_frame_table[2], "PING") then
       if debug then print (os.date("%c"), "[Request Handler] Received PING request. Calling PING Handler") end
       -- Ping found! Call PingHandler
       protocol_response = PING_handler ()
     elseif string.find (my_frame_table[2], "EOF") then
       -- Discard the EOF frame
       if debug then print (os.date("%c"), "[Request Handler] Received and discarded EOF frame") end
     else
       -- Discard the NOOP frame
       if debug then print (os.date("%c"), "[Request Handler] Received and discarded NOOP frame") end
     end

  end

  -- Send the frame back
  return protocol_response
end


function PageKite ( fe_socket )
  --
  -- This is the protocol handler.
  -- It's responsible to receive data frames from the Front end and push them over to 
  -- Request Handler to proceed with the request
  --

  local frame_size, frame_data, frame_response, frame_data_table, frame_header, status, partial, response_frame

  -- Start a big loop - look for frames arriving or for a closed remote connection
  if debug then print ( os.date("%c"), "[PageKite] Entering main loop...") end
  while true do
    -- Loop over the socket and keep reading data until it closes
    -- The first line should contain the frame size
    local frame_header, status, partial = fe_socket:receive ("*l")

    if status == "closed" then
      -- Remote peer closed the connection!
      if debug then
        if server_reconnect == 0 then
          print (os.date("%c"), "[PageKite] Remote connection closed! Exiting...")
        elseif server_reconnect == 1 then
          print (os.date("%c"), "[PageKite] Remote connection closed! Reconnecting...")
        end
      end
      -- Break out from the loop
      break
    end

    if status == "timeout" then
      -- Do a ping to the server to check the link status
      if not PingServer ( fe_socket ) then break end
    end

    if frame_header ~= nil then
      -- Get the first line of the frame. This should be the size of the chunk.
      frame_size = tonumber(frame_header, 16)
      if debug then print (os.date("%c"), "[PageKite] Incoming frame " .. frame_size .. " (0x" .. frame_header ..") bytes long") end

      -- Read the rest of the request to a buffer
      -- To do: Check the partial for any data left there!
      frame_data, status, partial = fe_socket:receive (frame_size)

      -- Push the frame data into a table for easy parsing
      frame_data_table = FrameToTable (frame_data)
      
      -- Call the Request Handler and get back a frame to send to the server
      if debug then print (os.date("%c"), "[PageKite] Calling RequestHandler") end
      response_frame = RequestHandler (frame_data_table)

      -- Send the request back to the front end
      -- If there is no response frame do not send anything (NOOP chunks)
      if response_frame ~= nil then
        if debug then
          response_frame_length = string.len(response_frame)
          print (os.date("%c"), "[PageKite] Sending " .. response_frame_length .. " bytes reply to FrontEnd") 
          end
        fe_socket:send ( response_frame )
      end
    end

    -- Wait for more data to arrive
    if debug then print ( os.date("%c"), "[PageKite] Waitting for data...") end
  end

end


--
-- Main Part
--

-- Run at least once and loop only if the user has defined server_reconnect as true.
repeat

  -- Main part
  print ("Starting Lua PageKite backend v" .. app_version .. "...")
  
  -- Start PhaseOne authentication process
  -- Get the challenge response back to proceed to the second phase.
  challenge, session_id = PhaseOne ()

  -- Check if we have a challenge string.
  if challenge then
    -- Phase One was completed successful. Move to phase 2
    remote_conn, error = PhaseTwo (challenge, session_id)

    -- Check if we passed Phase Two authentication
    if remote_conn then
      -- Authenticated with server.
      print ("Ready")
      -- Get the PageKite protocol handler
      PageKite (remote_conn)
    else
      -- Couldn't connect to remote server
      print ("Error connecting to remote server: " .. error)
    end
  end

  -- Try to reconnect to server after sleeping for 10 seconds
  if debug then print (os.date("%c"), "[PageKite] Reconnecting to server...") end
  
  -- Make a small pause before reconnecting to the server
  sleep (10)
  
-- Loop over
until server_reconnect == 0

