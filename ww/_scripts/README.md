# Wuthering Waves characters hash mods fix

## Usage

Download the file and run it inside the Mods folder or within an individual Mod. Please note that this fix is meant for Mods created with WWMI. Mods created with other tools are not included in this fix.

Video Tutorial for Visual Learners:

[Watch the step-by-step video tutorial](https://streamable.com/5w0pap).

### Build Command

```
PyInstaller --onefile --clean wuwa_fix.py
```

## Version

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
