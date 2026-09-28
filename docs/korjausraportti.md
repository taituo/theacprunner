# acp-runner: korjausraportti (V0–V10)

Päivitetty 2026-09-28. Toteuttaa dokumentit "acp-runner: korjaussuunnitelma" (V0–V10),
"Testaussuunnitelma" (esivaatimukset A ja B) ja "acp-runner: opencode ja mallinvalinta".

## Tulos lyhyesti

* Kaikki suunnitelman vaiheet V0–V10 on toteutettu, ja jokainen on oma commitinsa
  (`git log 1803dc0..HEAD`). Baseline on commit `1803dc0`.
* Lisäksi on tehty itsenäisen katselmoinnin korjaukset (commit `127cecc`).
* Testit: 240 läpi, 0 hylättyä, 0 ohitettua. Ajettu `ACP_REQUIRE_DB_TESTS=1`-asetuksella, jolloin DB- ja
  envtest-testit eivät voi hiljaa ohittua. Ympäristö: PostgreSQL 16 ja kube-apiserver v1.37
  (envtest). clippy `-D warnings` ja rustfmt ovat puhtaat.
* Uudet repot:
  * `acp-testbed`: sovellus, jolla on tagit `task/F1..F8/base` ja 7 `trap/*`-haaraa.
  * `acp-testbed-acceptance`: tehtävät, piilotestit, `verify.sh`, `selftest.sh` ja
    `run-suite.sh`.
  * `selftest` osoittaa, että piilotestit kaatuvat jokaisella basella ja menevät läpi
    referenssiratkaisulla.

## Vaiheittain

| Vaihe | Mitä tehtiin | Todisteet (testit) |
|---|---|---|
| V0 | Deterministinen CI. `ACP_REQUIRE_DB_TESTS` muuttaa ohitukset virheiksi. CRD-drift- ja cargo-deny-askeleet. | CI-työnkulku, `skip_or_fail` |
| V1 | Codex write-back. Controller lunastaa refresh tokenin itse, ja id_token varmennetaan (RS256/JWKS, iss/aud/exp, tilin sormenjälki). Hiekkalaatikon lähettämää tiedostoa ei koskaan tallenneta. Lease vapautuu vasta, kun backend raportoi podin poistuneen (Missing/Exited). | `forged_credential_writeback_is_rejected…`, `writeback_after_controller_cancel_is_accepted`, kube_e2e (fake-OAuth) |
| V2 | Luottamusraja. Profiilipolitiikka (nimiavaruudet/luokat, oletuksena kielto). `ACP_RUNNER_ALLOWED_IMAGES` (vain digestillä) ja `ACP_RUNNER_ALLOWED_SERVICE_ACCOUNTS`. `runnerctl auth allow`. | `profile_policy_restricts_who_may_lease`, `credential_profile_policy_limits_who_may_lease`, `image_and_service_account_allowlists_are_enforced` |
| V3 | Ingestin eheys. Varatut progress-kategoriat, artefaktin omistajuus (DB-triggerit), kohdennetut kyselyt. | `ingest_refuses_foreign_artifacts_and_runner_owned_categories` |
| V4 | Bootstrap ei näe tunnisteita: ne sijoitetaan vasta BootstrapDone-viestin jälkeen. Subreaper tappaa jälkeen jääneet prosessit (→ BootstrapFailed). cwd avataan `O_NOFOLLOW`-lipulla. | `bootstrap_runs_before_credentials_and_leaves_nothing_behind` |
| V5 | Pysyvät direktiivit (taulu, ack ja uudelleentoimitus, järjestys). Cancel menee jonon ohi. Heartbeatin rajoitus on DB-sarake. | `directives_are_ordered_redelivered_and_acked`, provider-testi |
| V6–V8 | Patch-hygienia (submodulet, tilat, `.git`-kirjainkoko). Egress-proxyn osoiteluokat (NAT64, 6to4, Teredo…). Gatewayn läpinäkyvyys ja kättelyraja. `file://` vain erikseen sallittuna. | workspace-, proxy- ja gateway-testit |
| V9 | Yleinen `acp`-ajuri. Launch-primitiivi `{command,args,env,files,cwd}`. `ACPRun.spec.overrides` (vain `allowRunOverrides`-luokille ja vain ensisijaiselle luokalle). Suojatut muuttujat. `files`-tunnisteprovider (`--select`, `--token-stdin`). `acp-conformance`-työkalu. opencode-ai 1.18.32 pinnattu. | `acp_launch_and_run_overrides`, conformance-testi, `drivers_lock` |
| V10 | AgentEnvironment-controller: finalizer, status, `spec.lifecycle`, gateway-Service, NetworkPolicy, RBAC. Tikettiavain Secretistä (`runnerctl env ticket`). Heartbeat-katko → Failed. Lease vapautuu vasta hiekkalaatikon kadottua. runnerd pysäyttää harnessin, jos controller on tavoittamattomissa. | `agent_environment_through_the_controller` (envtest), `lost_environment_is_failed_and_its_lease_fenced`, `harness_is_stopped_when_the_controller_stays_unreachable` |

## Testaamalla löydetyt asiat

* **AgentEnvironment ei olisi käynnistynyt Kubernetesissa lainkaan.** Luokan nimi
  `env:<harness>` meni pod-labeliksi, ja apiserver hylkää sen. Uusi envtest-e2e löysi
  virheen, ja label-arvot siistitään nyt.
* **opencode 1.18.32** (ilman oikeaa avainta, `acp-conformance`):
  * Konfiguraation etusija: globaali tiedosto < `OPENCODE_CONFIG` < repon `opencode.json` <
    `OPENCODE_CONFIG_CONTENT`. Luokan on siksi pidettävä oletusmalli ja
    tarjoajan endpoint `OPENCODE_CONFIG_CONTENT`issa.
  * Ansarepo, jonka `opencode.json` asetti baseURLiksi 127.0.0.1, ei tällä profiililla muuttanut
    mallia eikä sitä, minne pyynnöt menevät.
  * Ilman auth-merkintää malli vaihtuu `opencode/*`-malliin ja opencode ottaa yhteyden
    opencode.ai:hin. Kun malli on pakotettu, tulee `-32000 AuthRequired` (→ `AuthEnrollmentRequired`).
  * `acp --pure` poistaa ulkoiset pluginit käytöstä.
  * opencode ei sulkeudu stdinin EOF:iin, joten runtimen terminate-polku on tarpeen.
  * `session/new` palauttaa `configOptions`-kentän (model, effort, mode).

## Itsenäinen katselmointi (erillinen agentti) ja korjaukset

| Löydös | Korjaus |
|---|---|
| Epäonnistunut gateway-Service jätti podin käyntiin, ja lease vapautui | Pod ja Secret poistetaan, jos Service epäonnistuu |
| Branchit saivat owner-viitteen olemattomaan resurssiin (GC poistaisi) | `OwnerKind::Detached`: ei owner-viitteitä |
| Statuksesta kadonnut `environmentId` → poisto vuotaisi hiekkalaatikon | Environment haetaan omistajan uid:n perusteella |
| Controller-katkon fail-safe saattoi laueta vasta leasen rauettua | Tarkistus joka tickillä, heartbeat on aikarajattu, marginaali 120 s |
| Tallennusvirhe tarjoajan refreshin jälkeen hukkasi tokenit | Konfliktit yritetään uudelleen |
| `launch.cwd` seurasi symlinkkejä | cwd:n on ratkettava työtilan sisään |
| Overrides pystyi asettamaan `LD_PRELOAD`/`NODE_OPTIONS` | Kielletty ajotasolla (luokka voi asettaa) |

## Korjauksia alkuperäiseen katselmointiin

Löydös 11 (redaktointi) oli osittain väärä. Vähintään 16 merkin JSON-lehdet ja gateway-avain
rekisteröitiin redaktoriin jo alkuperäisessä koodissa. Varsinainen korjaustarve koski
refreshattuja tunnisteita ennen write-backia, ja se on korjattu (V6–V8).

## Mitä ei voitu todentaa tässä ympäristössä

* KIND / L2: konttirekisterit olivat estettyjä, joten imageja ei voinut rakentaa.
* L3 eli oikea monisolmuinen klusteri (gVisor, Cilium/Calico, KMS, kaaostestit).
* Live-ajo oikealla OpenAI-avaimella: opencoden prompt/cancel-profiili sekä testbedin F1–F8
  (`run-suite.sh`) oikeilla malleilla.
* `cargo deny check advisories`: advisory-tietokantaa ei voitu hakea. `licenses` menee läpi.

Nämä on skriptattu. Ensimmäinen ajo on hyväksymisaskel:

* `scripts/e2e-kind.sh`
* `ACP_CONFORMANCE_AUTH_JSON=… scripts/conformance.sh`
* `acp-testbed-acceptance/run-suite.sh`

## Tunnetut rajoitukset (dokumentoitu README:hen)

* `allowRunOverrides` antaa ajolle vallan harnessin konfiguraatioon. Se myönnetään vain
  nimiavaruuksille, joihin profiilipolitiikka jo luottaa.
* Mallin vaihto ajotasolla korvaa koko `OPENCODE_CONFIG_CONTENT`-arvon, joten ajon on
  toistettava endpoint. Egress-proxyn allowlist rajaa silti, minne avain voi mennä.
* Provider-API:lla luodut ympäristöt ja branchit eivät ole controllerin hallinnassa. Provider
  päättää ne tai tunnistaa heartbeat-katkon.
* Write-backissa lease-rivin lukko pidetään auki kahden HTTP-kutsun ajan (token + JWKS, max 20 s
  kumpikin).
* F7 (katselmointi) antaa F3:n referenssimuutoksen promptissa diffinä, ei overlayna.
