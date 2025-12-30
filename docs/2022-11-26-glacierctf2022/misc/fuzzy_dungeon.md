# Challenge

This game is so hard, I've spent the last few weeks trying to beat it but i'm not able to 😦 Can you help me?

nc pwn.glacierctf.com 13373

# Writeup

Dunno, just fortunate enough to pick the sword and won the fight:

```
-----------------------------------------------------------------------------------------------------
This is your turn number: 0
Welcome to the FuzzyDungeon. If you are able to make it to the black knight and manage to beat him he will reward you with his treasure. You see the door to the dungeon in front of you.

You can do the following things:
S - See your Stats
C - Go to the door

Enter your choice:
C
-----------------------------------------------------------------------------------------------------
This is your turn number: 1
You have entered the entry hall. The walls are decorated with old pictures. You are starting to rethink your idea of slaying the beast and getting the treasure. After some thoughts you commence and see two doors at the end of the hall.

You can do the following things:
S - See your Stats
R - Go to the right door
L - Go to the left door

Enter your choice:
L
-----------------------------------------------------------------------------------------------------
This is your turn number: 2
You seem to be lucky. After you step through the door you see a sword that looks way stronger than your current one lying on a table. At the end of the room there is one door.

You can do the following things:
S - See your Stats
C - Go to the door
A - Pick up the sword

Enter your choice:
A
You pick up the sword. Your damage has increased by 3 points.

You can do the following things:
S - See your Stats
C - Go to the door

Enter your choice:
C
-----------------------------------------------------------------------------------------------------
This is your turn number: 3
The room you enter looks like a greek temple. After taking some time to look at statues of a lot of naked people you find a small hidden door. The way further into the dungeon goes to the right.

You can do the following things:
S - See your Stats
R - Go to the right door
L - Go to the hidden door

Enter your choice:
L
-----------------------------------------------------------------------------------------------------
This is your turn number: 4
You investigate the hidden door and it doesn't seem that stable. You could try to smash it open using your sword.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
A
You hit the door with your sword a few times. It doesn't seem to help.
 You chip a part of your sword. Your damage decreases by 3.

You can do the following things:
S - See your Stats
R - Go back into the temple
A - Hit the door with your sword

Enter your choice:
R

-----------------------------------------------------------------------------------------------------
This is your turn number: 5
The room you enter looks like a greek temple. After taking some time to look at statues of a lot of naked people you find a small hidden door. The way further into the dungeon goes to the right.

You can do the following things:
S - See your Stats
R - Go to the right door
L - Go to the hidden door

Enter your choice:
Invalid Input, only one char is allowed
-----------------------------------------------------------------------------------------------------
This is your turn number: 6
You enter a beautiful room with a fountain and a small red bottle next to it. The room ends in a door.

You can do the following things:
S - See your Stats
C - Go to the door
A - Drink the potion

Enter your choice:
A
You drink the Potion. Your health gets fully replenished.

You can do the following things:
S - See your Stats
C - Go to the door

Enter your choice:
C
-----------------------------------------------------------------------------------------------------
This is your turn number: 7
The door opens up to a hall in which a group of bards train to impress the black knight. You take some time to watch them, rest and amuse yourself. You can now choose to go to the left or right.

You can do the following things:
S - See your Stats
R - Go to the right door
L - Go to the left door

Enter your choice:
L
-----------------------------------------------------------------------------------------------------
This is your turn number: 8
You walk through the door and directly fall into a hole. As you get up again you realize that you fell into a dwarfs home and destroyed half his house in the process. The dwarf doesn't care about your excuses and charges you. If you defeat him you can commence further.


-----------------------------------------------------------------------------------------------------
You attack the enemy. Your weapon has a damage of 65517.
Scratch!

You reduce your enemys health to 0 HP.
-----------------------------------------------------------------------------------------------------
You won this fight :)

You can do the following things:
S - See your Stats
C - Go to the door

Enter your choice:
C
-----------------------------------------------------------------------------------------------------
This is your turn number: 9
The door leads to an old armory. After taking some time digging through all kinds of armor you find a helmet in A+ condition. There is a giant door to the right which seems to lead to an important place.

You can do the following things:
S - See your Stats
R - Go to the right door
A - Pick up the helmet

Enter your choice:
A
You pick up the helmet. Your health gets increased by 10

You can do the following things:
S - See your Stats
R - Go to the right door

Enter your choice:
R
-----------------------------------------------------------------------------------------------------
This is your turn number: 10
You enter the black knights chamber. He smiles and says: "I didn't think you would make it this far.".


-----------------------------------------------------------------------------------------------------
You attack the enemy. Your weapon has a damage of 65517.
Bang!

You reduce your enemys health to 0 HP.
-----------------------------------------------------------------------------------------------------
You won this fight :)
glacierctf{1t5_oNlY_4_fl35h_w0unD}
-----------------------------------------------------------------------------------------------------
```

Since the damage is 65517, the might be integer underflow.