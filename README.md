# KrustyLoader Analysis

This repository contains resources related to the analysis made on KrustyLoader and available on this blog post: https://www.synacktiv.com/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises. 
- a Python script to extract and decrypt URL used by the downloader to get additional payloads 
- and a YARA rule to detect other KrustyLoader samples

## IOC

- IOC from Volexity: https://github.com/volexity/threat-intel/blob/main/2024/2024-01-18%20Ivanti%20Connect%20Secure%20pt3/indicators/iocs.csv
- For each line:
  - The sha256sum of the sample
  - The URL contacted by the sample to retrieve the Sliver backdoor
  - The Sliver C2 domain name

| sha256 | Stage URL | Sliver C2 |
| ------ | ----------- | --------- |
| 47ff0ae9220a09bfad2a2fb1e2fa2c8ffe5e9cb0466646e2a940ac2e0cf55d04 | `hxxp://blog-app-system2.s3.amazonaws[.]com/CGK63gVfWs52h` | `hxxps://update.sysupdates[.]org` |
| 816754f6eaf72d2e9c69fe09dcbe50576f7a052a1a450c2a19f01f57a6e13c17 | `hxxp://beansdeals-static.s3.amazonaws[.]com/1vzo0KenG4IKN` | `hxxps://api.farstream[.]org` |
| c26da19e17423ce4cb4c8c47ebc61d009e77fc1ac4e87ce548cf25b8e4f4dc28 | `hxxp://breaknlinks.s3.amazonaws[.]com/Bx8DH5OhdG3hY` | `hxxps://ntp.sysupdates[.]org` |
| c7ddd58dcb7d9e752157302d516de5492a70be30099c2f806cb15db49d466026 | `hxxp://be-at-home.s3.ap-northeast-2.amazonaws[.]com/2ekjMjslSG9uI` | `hxxps://music.farstream[.]org` |
| d14122fa7883b89747f273c44b1f71b81669a088764e97256f97b4b20d945ed0 | `hxxp://acapros-app.s3-us-west-2.amazonaws[.]com/Z0RM2DsTiBrmb` | Forbidden 403 on Stage Host |
| 6f684f3a8841d5665d083dcf62e67b19e141d845f6c13ee8ba0b6ccdec591a01 | `hxxp://acapros-app.s3-us-west-2.amazonaws[.]com/Lf6ceJhYiO7w4` | Forbidden 403 on Stage Host |
| a4e1b07bb8d6685755feca89899d9ead490efa9a6b6ccc00af6aaea071549960 | `hxxp://bbr-promo.s3.amazonaws[.]com/NWEUW983Ve4g1` | `hxxps://update.sysupdates[.]org` |
| ef792687b8bcd3c03bed4b09c4722bba921536802afe01f7cdb01cc7c3c60815 | `hxxp://bigtimeassets.s3.amazonaws[.]com/sTj9glpy3JMw5` | `hxxps://music.farstream[.]org` |
| 76902d101997df43cd6d3ac10470314a82cb73fa91d212b97c8f210d1fa8271f | `hxxp://ahha-asset.s3.ap-northeast-2.amazonaws[.]com/7J0WhInu49Teg`  | `hxxps://ntp.sysupdates[.]org` |
| e47b86b8df43c8c1898abef15b8b7feffe533ae4e1a09e7294dd95f752b0fbb2 | `hxxp://bringthenoiseappnew.s3.amazonaws[.]com/mi1FLmycM4of4` | `hxxps://check.sysupdates[.]org` |
| 73657c062a7cc50a3d51853ec4df904bcb291fdc9cdd08eecaecb78826eb49b6 | `hxxp://2261992.s3.amazonaws[.]com/kvdoEAH0y495p` | `hxxps://video.farstream[.]org` | 
| 030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0 | `hxxp://bringthenoiseappnew.s3.amazonaws[.]com/iEgJ4J7Uc9YgC` | `hxxps://ntp.sysupdates[.]org` |

List of the IOC formatted for easy copy/paste (thanks Ivan!):

```
hxxp://blog-app-system2.s3.amazonaws[.]com/CGK63gVfWs52h
hxxp://beansdeals-static.s3.amazonaws[.]com/1vzo0KenG4IKN
hxxp://breaknlinks.s3.amazonaws[.]com/Bx8DH5OhdG3hY
hxxp://be-at-home.s3.ap-northeast-2.amazonaws[.]com/2ekjMjslSG9uI
hxxp://acapros-app.s3-us-west-2.amazonaws[.]com/Z0RM2DsTiBrmb
hxxp://acapros-app.s3-us-west-2.amazonaws[.]com/Lf6ceJhYiO7w4
hxxp://bbr-promo.s3.amazonaws[.]com/NWEUW983Ve4g1
hxxp://bigtimeassets.s3.amazonaws[.]com/sTj9glpy3JMw5
hxxp://ahha-asset.s3.ap-northeast-2.amazonaws[.]com/7J0WhInu49Teg
hxxp://bringthenoiseappnew.s3.amazonaws[.]com/mi1FLmycM4of4
hxxp://2261992.s3.amazonaws[.]com/kvdoEAH0y495p
hxxp://bringthenoiseappnew.s3.amazonaws[.]com/iEgJ4J7Uc9YgC
hxxps://update.sysupdates[.]org
hxxps://api.farstream[.]org
hxxps://ntp.sysupdates[.]org
hxxps://music.farstream[.]org
hxxps://update.sysupdates[.]org
hxxps://music.farstream[.]org
hxxps://ntp.sysupdates[.]org
hxxps://check.sysupdates[.]org
hxxps://video.farstream[.]org
```


## Copyright

2024 - Théo Letailleur, Synacktiv

## License

The contents of this repository are available under [AGPL License](./LICENSE)

## Contact

- Théo Letailleur: theo.letailleur@synacktiv.com
- CSIRT Synacktiv: csirt@synacktiv.com
