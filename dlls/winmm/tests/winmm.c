/*
 * WinMM miscellaneous tests
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

static void test_WOW32ResolveMultiMediaHandle(void)
{
    static const UINT types[] = {0, 1, 2, 3, 4, 5, 6, 7, ~0u};
    static const UINT directions[] = {0, 1, 2, 3, ~0u};
    static const DWORD handles[] = {0, 1, 0x8000, 0xffff, 0x12340000, 0xdeadbeef};
    BOOL (WINAPI *resolve)(UINT, UINT, WORD, WORD *, HANDLE, HANDLE *);
    HMODULE module = LoadLibraryA("winmm.dll");
    unsigned int i, j, k;
    HANDLE result32;
    WORD result16;
    BOOL ret;

    ok(!!module, "Failed to load winmm.dll, error %lu\n", GetLastError());
    if (!module) return;
    resolve = (void *)GetProcAddress(module, "WOW32ResolveMultiMediaHandle");
#ifdef __i386__
    ok(!!resolve, "WOW32ResolveMultiMediaHandle export is missing\n");
#endif
    if (!resolve)
    {
        win_skip("WOW32ResolveMultiMediaHandle is unavailable\n");
        FreeLibrary(module);
        return;
    }

    /* This test is a Win32 process, not an NTVDM WOW process. Even valid
     * conversion directions must fail without modifying either output.
     */
    for (i = 0; i < ARRAY_SIZE(types); ++i)
    for (j = 0; j < ARRAY_SIZE(directions); ++j)
    for (k = 0; k < ARRAY_SIZE(handles); ++k)
    {
        winetest_push_context("type %u, direction %u, handle %#lx", types[i], directions[j], handles[k]);
        result16 = 0x1234;
        result32 = ULongToHandle(0xdeadbeef);
        ret = resolve(types[i], directions[j], handles[k], &result16, ULongToHandle(handles[k]), &result32);
        ok(!ret, "Got %d\n", ret);
        ok(result16 == 0x1234, "16-bit output changed to %#x\n", result16);
        ok(result32 == ULongToHandle(0xdeadbeef), "32-bit output changed to %p\n", result32);

        result16 = 0x1234;
        ret = resolve(types[i], directions[j], handles[k], &result16, ULongToHandle(handles[k]), NULL);
        ok(!ret, "Got %d with NULL 32-bit output\n", ret);
        ok(result16 == 0x1234, "16-bit output changed to %#x\n", result16);

        result32 = ULongToHandle(0xdeadbeef);
        ret = resolve(types[i], directions[j], handles[k], NULL, ULongToHandle(handles[k]), &result32);
        ok(!ret, "Got %d with NULL 16-bit output\n", ret);
        ok(result32 == ULongToHandle(0xdeadbeef), "32-bit output changed to %p\n", result32);

        ret = resolve(types[i], directions[j], handles[k], NULL, ULongToHandle(handles[k]), NULL);
        ok(!ret, "Got %d with NULL outputs\n", ret);
        winetest_pop_context();
    }
    FreeLibrary(module);
}

START_TEST(winmm)
{
    test_WOW32ResolveMultiMediaHandle();
}
