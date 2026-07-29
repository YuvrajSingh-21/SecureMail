# Adversarial Generalization Retest

| Attack Type | Raw Text Before Normalization | Prediction |
| :--- | :--- | :--- |
| Whitespace Injection | `U r g e n t :  V e r i f y   y o u r   a c c o u n t   i m m e d i a t e l y .  L o g i n .` | **SAFE** |
| Zero-width Characters | `U​r​g​e​n​t​: Verify your account immediately to prevent suspension. Click here to login.` | **SAFE** |
| Unicode Homographs | `Urgent: Ѳerify your аccount immediаtely. Lоgin.` | **SAFE** |
| HTML Obfuscation | `Urg<span></span>ent: Verify your acc<b></b>ount immediately. Log<!-- hidden -->in.` | **SAFE** |
| Mixed Casing | `uRgEnT: VeRiFy YoUr AcCoUnT iMmEdIaTeLy. LoGiN.` | **SAFE** |

*Conclusion: By combining HTML unwrapping, NFKC normalization, zero-width stripping, and Character N-Grams, the model successfully detects structural obfuscation that previously bypassed TF-IDF.*