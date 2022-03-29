# keroloader2

A small and incredibly hackish HLE emulator implementing a subset of Win32/DirectX APIs. 

It was initially designed to run a game called "Kero Blaster" to Android (hence the project's name), till I got hired to make an official port.

The code in this repo doesn't even run Kero Blaster anymore since I wanted to clean up and reuse the code for a completely 
unrelated game afterwards. I don't think this being open-sourced is interfering with the fact I did an official port, 
since the emulated port before giving up on this was incredibly glitchy and did not even had working sound and crashed on Android 11. 
The code itself is incredibly hackish and may need some cleanup before actually using it for anything else since the 
development mindset was "just get this done in a dirty and quick way". The last thing I remember working on later was 
getting relocations and VS 2013 C++ runtime to work since the .dll dependencies are a bit more complex than in aforementioned game. 
Threading also doesn't work and I don't think you will ever get real multithreading (instead of context switching on a single thread) 
unless you migrate away from Unicorn which [seems to have pretty big issues with it so far](https://github.com/unicorn-engine/unicorn/issues/142).

Since I'm not interested in messing with this anymore and I thought that this code might be useful for someone else I just decided to open-source it.

Enjoy.
