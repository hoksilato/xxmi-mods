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
