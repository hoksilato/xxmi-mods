# Wuthering Waves characters hash mods fix

## Usage

Download the file and run it inside the Mods folder or within an individual Mod. Please note that this fix is meant for Mods created with WWMI. Mods created with other tools are not included in this fix.

Video Tutorial for Visual Learners:

[Watch the step-by-step video tutorial](https://streamable.com/5w0pap).

**PS**: IF you're using the source code remember to move the `FixTexture.zip` to the same path that you are using the code.

### Build Command

```
pyinstaller --onefile --add-data "version_info.txt;." --add-data "manifest.xml;." --version-file=version_info.txt --manifest=manifest.xml --add-data "./FixTexture.zip;." wuwa_fix.py
```

## Version

> Author: Gustav0

### 1.4 - [Link](https://gamebanana.com/tools/18446)

Only a few characters have been affected by this patch, with some changes being more notable than others.

#### LightMap / FaceShadow Issue

Several characters in the game share this texture, such as Yangyan, Chixia, and others. In this patch, not only the hash but the texture itself was changed. If a single mod uses the old texture, it will conflict with all others since the hash is shared.

The script searches for the old texture and replaces it. If the issue is still not resolved, search through the mods until you find the culprit.

**IMPORTANT**

If your mod is broken and the First line after `[Constants]` is something like this:

```
global $required_wwmi_version = 0.61
```

If the version is bellow `0.70` the mod can't be fixed, you need to press <kbd>ALT + F12</kbd> to enable compatibility mode and pray, it will glitch.
You can ping me on AGMG and I can give a proper look if is the case.

**REMEMBER**

I don't have a crystal ball to know why "n" mod wasn't just fixed with just name, the minimum expected is that they send the link to the mod (gamebanana only).

Changli is a very complex case; some mods in component mode and merged aswell can be fixed, but there are some Changli mods that are impossible to fix with scripts alone.

#### Broken Characters

- Changli
- Rover (Female)
- Jianxin

The trigger to remap the `Changli` fingers is the hash: `060f5303` (Shapekeys Hash). If, for some reason, your Changli mod is already  have this hash updated, it will not trigger. Also, as I’ve mentioned many times, not all Changli mods can be fixed without re-exporting them. Everything depends on how the modder created the assets.

### 1.3 - [Link](https://gamebanana.com/tools/18109)

> Author: Gustav0

Only a few characters have been affected by this patch, with some changes being more notable than others.

#### Broken Characters

- Verina
- Yinlin
- Rover (Female)
- Rover (Male)
- Jianxin
  - Fix the issue with Jianxin's mouth, as it required special treatment. The checksum for the shapekeys has been altered.
- Chixia
- Yangyang
- Sanhua
  - New face lightmap

#### LightMap / FaceShadow Issue

Several characters in the game share this texture, such as Yangyan, Chixia, and others. In this patch, not only the hash but the texture itself was changed. If a single mod uses the old texture, it will conflict with all others since the hash is shared.

The script searches for the old texture and replaces it. If the issue is still not resolved, search through the mods until you find the culprit.

### 1.2 - [Link](https://gamebanana.com/tools/17752)

> Author: Gustav0

> Does not work for mods made using `Per-Component`

Only a few characters have been affected by this patch, with some changes being more notable than others.

#### Minor Changes (Hash Change)

The following characters have only undergone changes to their hashes:

- Calcharo
- Rover (Female and Male)
- Baizhi
- Yinlin
- Jiyan

#### Major Changes (Remap)

##### Verina

Has undergone a remap in her vertex groups, making this fix more complex.

- If you have run a previous fix on Verina, download the mod again and run it fresh, as it will cause conflict and not perform the remap.

#### Complex Changes

##### Changli

Has undergone the most significant changes in this patch, with her cape being re-weighted and new vertices added. Due to the large number of vertex groups, her fix was more challenging.
