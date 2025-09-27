# Spy PLC

```
PLC operators have detected that the test mode has been activated and intruders have sent a message through it. What message is this PLC transmitting?

Note: Find the spy PLC message and wrap with ASIS{}!
```

Attachment:

```
PROGRAM ENVMon
	VAR
		TempRaw AT %IW0 : INT;
		HumRaw AT %IW1 : INT;
		PressRaw AT %IW2 : INT;
		GasRaw AT %IW3 : INT;
	END_VAR
	VAR CONSTANT
		T_Thr_Max : INT := 1200;
		H_Thr_Max : INT := 900;
		P_Thr_Max : INT := 3000;
		G_Thr_Max : INT := 1000;
		T_Thr_Min : INT := 200;
		H_Thr_Min : INT := 200;
		P_Thr_Min : INT := 500;
		G_Thr_Min : INT := 100;
	END_VAR
	VAR
		StrongHeat AT %QX0.0 : BOOL;
		ColdHumid AT %QX0.1 : BOOL;
		HighPress AT %QX0.2 : BOOL;
		LowPress AT %QX0.3 : BOOL;
		LowGas AT %QX0.4 : BOOL;
		HighGas AT %QX0.5 : BOOL;
		HeatAndPressure AT %QX0.6 : BOOL;
		DryAndGas AT %QX0.7 : BOOL;
	END_VAR
	VAR
		TestMode : BOOL := True;
		StepSelect : INT := 1;
		AutoPlay : BOOL := True;
		stepP : INT := 1;
		Tmr : TON;
	END_VAR
	VAR
		TT AT %MW0 : INT;
		HH AT %MW1 : INT;
		PP AT %MW2 : INT;
		GG AT %MW3 : INT;
	END_VAR
	VAR
		TEMP_CASES : ARRAY [1..32] OF INT := [180, 180, 1300, 1300, 1300, 180, 900, 1300, 1300, 180, 180, 400, 1300, 180, 400, 400, 900, 180, 1300, 180, 900, 1300, 400, 900, 180, 400, 1300, 180, 900, 400, 1300, 400];
		HUM_CASES : ARRAY [1..32] OF INT := [150, 1000, 150, 150, 1000, 400, 150, 150, 1000, 400, 800, 400, 1000, 800, 400, 150, 150, 400, 1000, 150, 400, 1000, 150, 1000, 400, 400, 150, 400, 150, 800, 150, 400];
		PRESS_CASES : ARRAY [1..32] OF INT := [1000, 400, 400, 3500, 1000, 3500, 3500, 3500, 1000, 3500, 400, 2000, 1000, 2000, 2000, 2000, 1000, 1000, 1000, 3500, 2000, 1000, 3500, 2000, 2000, 1000, 3500, 3500, 3500, 2000, 3500, 3500];
		GAS_CASES : ARRAY [1..32] OF INT := [300, 300, 300, 300, 300, 50, 300, 50, 300, 300, 300, 300, 300, 300, 300, 300, 300, 300, 300, 50, 300, 300, 50, 300, 300, 300, 300, 300, 300, 300, 50, 50];
		NCASES : INT := 32;
		T_mid : INT;
		H_mid : INT;
		P_mid : INT;
		G_mid : INT;
		Tz : INT;
		Hz : INT;
		Pz : INT;
		Gz : INT;
	END_VAR

	T_mid := (T_Thr_Min + T_Thr_Max) / 2;
	H_mid := (H_Thr_Min + H_Thr_Max) / 2;
	P_mid := (P_Thr_Min + P_Thr_Max) / 2;
	G_mid := (G_Thr_Min + G_Thr_Max) / 2;

	IF TempRaw <= T_Thr_Min THEN 
		Tz := 0;
	ELSIF TempRaw <= T_mid THEN 
		Tz := 1;
	ELSIF TempRaw < T_Thr_Max THEN 
		Tz := 2;
	ELSE 
		Tz := 3;
	END_IF;

	IF HumRaw <= H_Thr_Min THEN 
		Hz := 0;
	ELSIF HumRaw <= H_mid THEN 
		Hz := 1;
	ELSIF HumRaw < H_Thr_Max THEN 
		Hz := 2;
	ELSE 
		Hz := 3;
	END_IF;

	IF PressRaw <= P_Thr_Min THEN 
		Pz := 0;
	ELSIF PressRaw <= P_mid THEN 
		Pz := 1;
	ELSIF PressRaw < P_Thr_Max THEN 
		Pz := 2;
	ELSE 
		Pz := 3; 
	END_IF;

	IF GasRaw <= G_Thr_Min THEN 
		Gz := 0;
	ELSIF GasRaw <= G_mid THEN 
		Gz := 1;
	ELSIF GasRaw < G_Thr_Max THEN 
		Gz := 2;
	ELSE 
		Gz := 3; 
	END_IF;
	 
	IF TestMode THEN
			IF AutoPlay THEN
					Tmr(IN:=TRUE, PT:=T#2000ms);
					IF Tmr.Q THEN
							stepP := stepP + 1;
							IF stepP > NCASES THEN stepP := 1; END_IF;
							Tmr(IN:=FALSE);
					END_IF;
					IF NOT Tmr.Q THEN Tmr(IN:=TRUE); END_IF;
			ELSE
					IF StepSelect < 1 THEN stepP := 1;
					ELSIF StepSelect > NCASES THEN stepP := NCASES;
					ELSE stepP := StepSelect;
					END_IF;
			END_IF;
			TempRaw := TEMP_CASES[stepP];
			HumRaw := HUM_CASES[stepP];
			PressRaw := PRESS_CASES[stepP];
			GasRaw := GAS_CASES[stepP];

	END_IF;
	StrongHeat := (Tz = 1) OR (Tz = 3);
	ColdHumid := (Tz >= 2);
	HighPress := (Hz = 1) OR (Hz = 3);
	LowPress := (Hz >= 2);
	HighGas := (Pz = 1) OR (Pz = 3);
	LowGas := (Pz >= 2);
	HeatAndPressure := (Gz = 1) OR (Gz = 3);
	DryAndGas := (Gz >= 2);

END_PROGRAM

CONFIGURATION Config0
	RESOURCE Res0 ON PLC
		TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
		PROGRAM instance0 WITH task0 : ENVMon;
	END_RESOURCE
END_CONFIGURATION
```

Ask ChatGPT to solve it:

```
Solve CTF challenge:

<attachment here>
```

Response:

```
Nice one — the program’s outputs are wired to the wrong zone variables (the boolean outputs use the wrong `*z` variables), so the 8 QX outputs per test case form bytes. I simulated the 32 test cases, read the 8 booleans per case (in the order they appear in the code), reversed each 8-bit sequence (LSB first), and converted to ASCII.

The recovered message is:

PLCs_4r3_tHe_heaRT_0f_1ndUstri35

So the CTF flag (wrapped in the usual format) is:

crew{PLCs_4r3_tHe_heaRT_0f_1ndUstri35}

If you want, I can paste the short Python simulation I used to extract it.
```

Flag: `ASIS{PLCs_4r3_tHe_heaRT_0f_1ndUstri35}`.
