# Zavrsni-rad - grana bulletproofs

Arhitektura sustava je ista kao na main grani, a ovdje cu opisati dio koji je drugaciji.


## Funkcionalnosti

- Issuer generira ZKP (bulletproof) za dob usera (holdera) i daje mu na koristenje
--- za maloljetne usere se ne generira valjan dokaz, na taj nacin se osigurava provjera dobi
- Holder prezentira dobiveni bulletproof verifieru
- Verifier provjerava dobivenu prezentaciju ne znajuci nista o godinama holdera

## Pokretanje

### Izgradnja `pybulletproofs`

Ovaj dio projekta ukljucuje ekstenziju (`pybulletproofs`). Koraci za izgradnju:

```bash
python -m venv venv310
source venv310/Scripts/activate
pip install -r requirements.txt
cd pybulletproofs
maturin develop --release
```

Napomene:
- maturin je neophodan za kompajliranje Rust ekstenzije; on se nalazi na popisu u requirements.txt. 
- nativni instalacijski paket specifican je za Python interpreter koji je koristen za njegovu izgradnju. Ako promijenite virtualno okruzenje (venv), morate ponovno izgraditi pybulletproofs u tom novom okruzenju. 
- kao alternativu za brže testiranje (iteraciju), mozete koristiti naredbu maturin develop (bez --release) kako biste izbjegli dugotrajnu izgradnju pune "release" verzije. 

Virtualno okruzenje bi se trebalo samostalno aktivirati, ali ako ne:

```bash
source venv310/Scripts/activate
```

## Pokretanje sustava i demonstracije

Virtualno okruzenje bi se trebalo samo aktivirati u novom bash terminalu, ali ako ne:
```bash
source venv310/Scripts/activate
```

Nakon toga redom u zasebnim terminalima:

```bash
python issuer.py
```

```bash
python verifier.py
```

```bash
python holder.py
```

## Demonstacija

- koriste se dva usera, fran (punoljetan) i ana (maloljetna)
- postoje 2 verifiera: 1 koji trazi dokaz i 1 koji ne trazi
- i fran i ana prolaze test kod verifiera koji ne trazi dokaz
- fran prolazi, a ana pada test kod verifiera koji trazi dokaz (invalid_age_proof)
- ana pokusava izvesti napad zamjenom: koristi franov dokaz, ali ni to ne prolazi (invalid_age_proof)


## Ogranicenja

- koristena biblioteka (pybulletproofs) ne podrzava generiranje dokaza pomocu zadanog blinding factora, sto znaci da holder ne moze samostalno kreirati dokaze
- ZKP je zato ostvaren na Issuer strani, tj samo Issuer moze generirati potreban dokaz
- time je donekle narusen unlinkability


