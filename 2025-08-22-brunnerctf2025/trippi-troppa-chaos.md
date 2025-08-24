# Trippi Troppa Chaos

```
Difficulty: Medium
Author: ha1fdan

The baker got infected with Italian brainrot and obfuscated our flag encoder with memes and nested functions. Can you help us find our flag?
```

Attachment:

```python
#!/usr/bin/env python3
import sys as _tralalero_tralala_impostor_____
(lambda _bombardiro_crocodilo___: [
    setattr(__builtins__, '__boneca_ambalabu_toilet____', __import__('base64').b85encode),
    setattr(__builtins__, '___trippa_troppa_mewing___', __import__('hashlib').sha256),
    setattr(__builtins__, '__tung_tung_sahur_cycle_____', __import__('itertools').cycle),
    setattr(__builtins__, '____pinguino_arrabiato_seed____', __import__('random').seed)
][_bombardiro_crocodilo___] and None)(0) or ____pinguino_arrabiato_seed____(69420)

def ___ranocchio_turbina_function_factory____():
    def ____lirilì_rilà_final_boss_____():
        def _____trippi_troppa_skibidi_____():
            def ______crocodina_gigachad_nested______():
                def _______tralala_alpha_transformation_______():
                    def ________boneca_beta_elimination________():
                        def _________sahur_sigma_activities_________():
                            def __________bombardiro_mewing__________():
                                def ___________trippa_no_cap___________():
                                    def ____________tung_bussin_respectfully____________():
                                        def _____________tralalero_slay_queen_energy_____________():
                                            __fanum_tax_pinguino____ = lambda ___cringe_normie_bombardiro___, ____based_chad_crocodilo____: (lambda ____uwu_owo_tralalero____: [__c__ for __c__ in ____uwu_owo_tralalero____])(
                                                [___x___ ^ ___y___ for ___x___, ___y___ in zip(___cringe_normie_bombardiro___, __tung_tung_sahur_cycle_____(____based_chad_crocodilo____))]
                                            )
                                            
                                            def ____boneca_ambalabu_university____(___x_trippa___, ___y_troppa___):
                                                return (lambda ____bruh_moment_lirilì____: ____bruh_moment_lirilì____.digest()[:len(___y_troppa___)])(
                                                    ___trippa_troppa_mewing___(
                                                        ((___x_trippa___.decode() if isinstance(___x_trippa___, bytes) else ___x_trippa___) + 
                                                         (___y_troppa___.decode() if isinstance(___y_troppa___, bytes) else ___y_troppa___)).encode()
                                                    )
                                                )
                                            
                                            def ____tralalero_griddy_dance____(___x_ranocchio___):
                                                return (lambda ____fortnite_bombardiro_pass____: 
                                                       [___c_crocodina___ for ___c_crocodina___ in ____fortnite_bombardiro_pass____]
                                                )([((___c_sahur___ * 7) % 256) for ___c_sahur___ in ___x_ranocchio___])
                                            
                                            def ____tung_reverse_uno_card____(___x_pinguino___):
                                                return (lambda ____amogus_sus_trippi____: ____amogus_sus_trippi____[::-1])(___x_pinguino___)
                                            
                                            def ____dead_meme_boneca_graveyard____():
                                                ____poggers_tralala____, ____chungus_rilà____, ____keanu_troppa____ = 1337, 420, 9000
                                                for ___i_bombardiro___ in (lambda ___x_crocodilo___: range(___x_crocodilo___))(5):
                                                    ____poggers_tralala____ = (____poggers_tralala____ * ____chungus_rilà____ + ____keanu_troppa____) % (___i_bombardiro___ + 7)
                                                return ____poggers_tralala____
                                            
                                            def ____touch_grass_tralalero_function____():
                                                try:
                                                    with open("flag.txt", "rb") as ____yeet_file_ambalabu____:
                                                        ____cringe_flag_pinguino____ = ____yeet_file_ambalabu____.read()
                                                except:
                                                    return "L + ratio + skill issue + no tralalero for you"
                                                
                                                ____sussy_key_bombardiro____ = b"skibidi"
                                                
                                                ____step_one_boneca____ = ____boneca_ambalabu_university____(____sussy_key_bombardiro____, ____sussy_key_bombardiro____)
                                                ____step_two_sahur____ = bytes(__fanum_tax_pinguino____(____cringe_flag_pinguino____, ____step_one_boneca____))
                                                ____step_three_trippa____ = bytes(____tralalero_griddy_dance____(____step_two_sahur____))
                                                ____step_four_troppa____ = ____tung_reverse_uno_card____(____step_three_trippa____)
                                                ____final_boss_crocodina____ = __boneca_ambalabu_toilet____(____step_four_troppa____).decode()
                                                
                                                return ____final_boss_crocodina____
                                            
                                            return ____touch_grass_tralalero_function____
                                        return _____________tralalero_slay_queen_energy_____________
                                    return ____________tung_bussin_respectfully____________
                                return ___________trippa_no_cap___________
                            return __________bombardiro_mewing__________
                        return _________sahur_sigma_activities_________
                    return ________boneca_beta_elimination________
                return _______tralala_alpha_transformation_______
            return ______crocodina_gigachad_nested______
        return _____trippi_troppa_skibidi_____
    return ____lirilì_rilà_final_boss_____

if __name__ == "__main__":
    print((lambda ___x_tralalero___: ___x_tralalero___()()()()()()()()()()()())(___ranocchio_turbina_function_factory____))
```

The code essentially:

1. run sha256 on `"skibidi" + "skibidi"`
2. xor flag and the output of first step
3. for each character, mul 7 mod 256
4. reverse
5. base85 encode

Reverse the steps to get the flag:

```python
import base64
import hashlib
import itertools

text = (
    "qjuA_QZVI_ua24NQ}fM1hX4ecdyVShKb2vJjeQJ@Jz=zws0^9Enr1fR+Em_5w2j=p4)2<#m3EZ?m3Oo@"
)
text = base64.b85decode(text)
text = text[::-1]
text = bytes([(ch * pow(7, -1, 256) % 256) for ch in text])
key1 = b"skibidi"
key = hashlib.sha256((key1.decode() + key1.decode()).encode()).digest()[:len(key1)]
text = bytes([ch1 ^ ch2 for ch1, ch2 in zip(text, itertools.cycle(key))])
print(text)
```

Get flag: `brunner{tr4l4l3r0_b0mb4rd1r0_r3v3rs3_3ng1n33r1ng_sk1b1d1_m4st3r}`
