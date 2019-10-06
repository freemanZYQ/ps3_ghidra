# ps3_ghidra
A collection of scripts/loaders/plugins for ghidra used to aid ps3 reverse engineering

## find_stdu.java

Here is stupid script made from one of already existing ones. You need to run it on unanalyzed file to get best result, or result at all until i learn java, and that api. 

Is just looking for hex pattern of      stdu        r1, and create function there. For now it scan only undefinied parts, that why need to run before analyze. Seems to not cause any issues, you can run autoanalyze right when it finish.

## ps3.py
nasty script
put ps3.xml in main ghidra folder
does imports and exports
only works on elfs for now
