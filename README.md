# Sustav za zaštitu privatnosti s podrškom za Zero-Knowledge Proof (ZKP) - završni rad

Ova grana nadograđuje osnovnu arhitekturu implementacijom Zero-Knowledge Range Proofs (ZKRP) protokola, konkretno Bulletproofs.
Dok se main grana oslanja na selektivno otkrivanje sirovih podataka, ovdje je demonstriran napredniji pristup: dokazivanje pripadnosti numeričkog atributa (dob korisnika) određenom rasponu bez otkrivanja same vrijednosti.

## Ključne funkcionalnosti

- **ZKP provjera punoljetnosti**: Korištenjem Bulletproofs algoritma, sustav omogućuje korisniku da dokaže verifikatoru da je punoljetan bez otkrivanja točnog datuma rođenja ili broja godina.
- **Issuer-side ZKP generiranje**: Zbog specifičnosti implementirane biblioteke, Issuer generira kriptografski dokaz (Bulletproof) isključivo za korisnike koji zadovoljavaju kriterij. Maloljetnim korisnicima se ne izdaje valjan dokaz, čime se onemogućuje lažna prezentacija.
- **Zaštita od napada zamjenom (Proof Substitution Attack)**: Sustav je dizajniran da detektira pokušaje u kojima jedan korisnik (npr. maloljetna Ana) pokušava iskoristiti presretnuti dokaz drugog korisnika (npr. punoljetni Fran). Verifikator odbija prezentaciju jer dokaz nije kriptografski povezan s identitetom (ključem) onoga tko ga prezentira.
- **Tehnička implementacija i izgradnja**: Ovaj dio projekta koristi pybulletproofs, Python binding za Rust, radi brzine i preciznosti.

## Izgradnja ekstenzije
Za uspješno pokretanje potrebno je kompajlirati Rust kod unutar Python virtualnog okruženja:
```bash
python -m venv venv310
source venv310/Scripts/activate
pip install -r requirements.txt
cd pybulletproofs
maturin develop --release
```
Napomena: Maturin alat je neophodan za povezivanje Rust koda s Python interpreterom. Budući da je paket specifičan za verziju interpretera, kod svake promjene venv okruženja potrebno je ponoviti maturin develop naredbu.

## Demonstracijski scenariji
U simulaciji sudjeluju dva korisnika: Fran (punoljetan) i Ana (maloljetna).
 - **Standardna verifikacija**: Oba korisnika uspješno pristupaju verifikatoru koji ne zahtijeva dokaz dobi.
 - **ZKP verifikacija**: Fran uspješno dokazuje punoljetnost. Ana ne može generirati niti prezentirati valjan dokaz te biva odbijena (invalid_age_proof).
 - **Simulacija napada**: Ana pokušava iskoristiti Franov dokaz punoljetnosti. Verifikator prepoznaje neslaganje između dokaza i korisničkog ključa (Key Binding) te odbija zahtjev.
  
## Ograničenja i sigurnosna analiza
- trenutna verzija biblioteke pybulletproofs ne podržava eksterni blinding factor, tj. ne može se stvoriti dokaz sa zadanim blinding factorom. Zbog toga Holder ne može samostalno generirati dokaz, već se mora osloniti na Issuer-a
- s obzirom na to da Issuer generira dokaz, teoretski bi mogao pratiti izdavanje istog, što djelomično utječe na potpunu nepovezivost (unlinkability), ali osigurava praktičnu primjenjivost u sustavima gdje Issuer ionako poznaje identitet korisnika u trenutku izdavanja.

