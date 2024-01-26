// KrustyLoader.yar
// Copyright (C) 2024 - Synacktiv, Théo Letailleur
// contact@synacktiv.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

rule Linux_Downloader_KrustyLoader
{
    meta:
        author = "Theo Letailleur, Synacktiv"
        source = "Synacktiv"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        category = "MALWARE"
        malware = "KrustyLoader"
        description = "Yara rule that detects Linux KrustyLoader"

    strings:
        $tokio_worker = "TOKIO_WORKER_THREADS"
        $tmpdir = "/tmp/"

        // Load "/proc/self/exe" string
        $proc_self_exe = {
            48 B? 73 65 6C 66 2F 65 78 65 // mov     r64, 6578652F666C6573h
            48 8D B4 24 ?? ?? 00 00       // lea     rsi, [rsp+????h]
            48 89 46 0?                   // mov     [rsi+6], r64
            48 B? 2F 70 72 6F 63 2F 73 65 // mov     r64, 65732F636F72702Fh
            48 89 0?                      // mov     [rsi], r64
        }

        $pipe_suffix = "|||||||||||||||||||||||||||"

        // AES key expansion
        $aeskeygenassist = {
            660F3ADF0601 // aeskeygenassist xmm0, xmmword ptr [rsi], 1
            660F7F07     // movdqa  xmmword ptr [rdi], xmm0
            C3           // retn
        }

        // AES InvMixColumns
        $aesinvmixcol = {
            660F38DB06  // aesimc  xmm0, xmmword ptr [rsi]
            660F7F07    // movdqa  xmmword ptr [rdi], xmm0
            C3          // retn
        }

    condition:
        uint32(0) == 0x464C457F and
        (
            all of them
        )
}