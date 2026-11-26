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
#include "winuser.h"
#include "mmsystem.h"
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

static void test_wow_message_exports(void)
{
#ifdef __i386__
    static const struct
    {
        const char *name;
        DWORD result;
    }
    tests[] =
    {
        {"aux32Message", MMSYSERR_NOTSUPPORTED},
        {"joy32Message", TIMERR_NOCANDO},
        {"mci32Message", 1},
        {"mid32Message", MMSYSERR_NOTSUPPORTED},
        {"mod32Message", MMSYSERR_NOTSUPPORTED},
        {"mxd32Message", MMSYSERR_NOTSUPPORTED},
        {"tid32Message", TIMERR_NOCANDO},
        {"wid32Message", MMSYSERR_NOTSUPPORTED},
        {"wod32Message", MMSYSERR_NOTSUPPORTED},
    };
    static const DWORD args[][5] =
    {
        {0, 0, 0, 0, 0},
        {1, 0, 0, 0, 0},
        {11, 0, 0, 0, 0},
        {0xdeadbeef, 0x12345678, 0x8000, 0xffff, 0xdeadbeef},
        {~0u, ~0u, ~0u, ~0u, ~0u},
    };
    HMODULE module = GetModuleHandleA("winmm.dll");
    DWORD (WINAPI *message)(DWORD, DWORD, DWORD, DWORD, DWORD);
    unsigned int i, j;
    DWORD ret;

    /* Ordinary Win32 callers must take the non-WOW path, regardless of
     * the opcode, handles or pointers encoded in the five arguments.
     */
    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        message = (void *)GetProcAddress(module, tests[i].name);
        ok(!!message, "%s export is missing\n", tests[i].name);
        if (!message) continue;
        for (j = 0; j < ARRAY_SIZE(args); ++j)
        {
            ret = message(args[j][0], args[j][1], args[j][2], args[j][3], args[j][4]);
            ok(ret == tests[i].result, "%s case %u returned %lu, expected %lu\n",
               tests[i].name, j, ret, tests[i].result);
        }
    }
#else
    win_skip("WOW message entry points are only tested on i386\n");
#endif
}

static void test_mmDrvInstall(void)
{
    typedef DWORD (WINAPI *driver_message_proc)(DWORD, DWORD, DWORD_PTR, DWORD_PTR, DWORD_PTR);
    UINT (WINAPI *install)(HDRVR, const WCHAR *, driver_message_proc, UINT);
    HMODULE module = GetModuleHandleA("winmm.dll");
    UINT ret;

    install = (void *)GetProcAddress(module, "mmDrvInstall");
    ok(!!install, "mmDrvInstall export is missing\n");
    if (!install) return;

    /* Category 15 is invalid. No driver, name or callback is needed. */
    ret = install(NULL, NULL, NULL, ~0u);
    ok(!ret, "mmDrvInstall returned %u for an invalid category\n", ret);
}

struct wow_app_exit_thread
{
    HANDLE ready, done, event;
    MMRESULT timers[3];
};

static MMRESULT create_wow_app_exit_timer(HANDLE event)
{
    MMRESULT timer;

    timer = timeSetEvent(60000, 0, event, 0, TIME_PERIODIC | TIME_CALLBACK_EVENT_SET);
    ok(!!timer, "Failed to create timer\n");
    return timer;
}

static DWORD WINAPI wow_app_exit_thread(void *arg)
{
    struct wow_app_exit_thread *data = arg;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(data->timers); ++i)
        data->timers[i] = create_wow_app_exit_timer(data->event);
    SetEvent(data->ready);
    WaitForSingleObject(data->done, INFINITE);
    return 0;
}

static MCIDEVICEID open_wow_app_exit_device(void)
{
    MCI_OPEN_PARMSA parms = {0};
    MCIERROR err;

    parms.lpstrDeviceType = "waveaudio";
    parms.lpstrElementName = "";
    err = mciSendCommandA(0, MCI_OPEN, MCI_OPEN_ELEMENT | MCI_OPEN_TYPE, (DWORD_PTR)&parms);
    if (err)
    {
        win_skip("Cannot open a new waveaudio device, error %lu\n", err);
        return 0;
    }
    ok((ULONG_PTR)mciGetCreatorTask(parms.wDeviceID) == GetCurrentThreadId(),
            "Unexpected creator task %p\n", mciGetCreatorTask(parms.wDeviceID));
    return parms.wDeviceID;
}

static void check_wow_app_exit_timer(MMRESULT *timer, MMRESULT expected)
{
    MMRESULT ret;

    if (!*timer) return;
    ret = timeKillEvent(*timer);
    ok(ret == expected, "timeKillEvent(%u) returned %u, expected %u\n", *timer, ret, expected);
    *timer = 0;
}

static void test_WOWAppExit(void)
{
    struct wow_app_exit_thread data = {0};
    DWORD thread_id, current_id = GetCurrentThreadId(), unmatched;
    HMODULE module = LoadLibraryA("winmm.dll");
    void (WINAPI *app_exit)(ULONG_PTR);
    MCIDEVICEID device = 0;
    MMRESULT timer = 0;
    HANDLE thread = NULL;
    unsigned int i;
    MCIERROR err;
    DWORD ret;

    ok(!!module, "Failed to load winmm.dll, error %lu\n", GetLastError());
    if (!module) return;
    app_exit = (void *)GetProcAddress(module, "WOWAppExit");
#ifdef __i386__
    ok(!!app_exit, "WOWAppExit export is missing\n");
#endif
    if (!app_exit)
    {
        win_skip("WOWAppExit is unavailable\n");
        FreeLibrary(module);
        return;
    }

    data.ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    data.done = CreateEventW(NULL, FALSE, FALSE, NULL);
    data.event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(!!data.ready && !!data.done && !!data.event, "Failed to create events, error %lu\n", GetLastError());
    if (!data.ready || !data.done || !data.event) goto done;
    thread = CreateThread(NULL, 0, wow_app_exit_thread, &data, 0, &thread_id);
    ok(!!thread, "Failed to create thread, error %lu\n", GetLastError());
    if (!thread) goto done;
    ret = WaitForSingleObject(data.ready, 10000);
    ok(ret == WAIT_OBJECT_0, "Wait returned %#lx\n", ret);
    if (ret != WAIT_OBJECT_0) goto done;

    device = open_wow_app_exit_device();
    timer = create_wow_app_exit_timer(data.event);
    unmatched = current_id ^ 0x80000000;
    if (!unmatched || unmatched == thread_id) unmatched ^= 0x40000000;
    app_exit(unmatched);
    app_exit(unmatched);
    if (device)
        ok((ULONG_PTR)mciGetCreatorTask(device) == current_id, "Unmatched task closed the MCI device\n");
    check_wow_app_exit_timer(&timer, TIMERR_NOERROR);
    check_wow_app_exit_timer(&data.timers[0], TIMERR_NOERROR);

#ifdef _WIN64
    /* MCI uses the full task value, but timer ownership uses only its low DWORD. */
    timer = create_wow_app_exit_timer(data.event);
    app_exit(((ULONG_PTR)1 << 32) | current_id);
    if (device)
        ok((ULONG_PTR)mciGetCreatorTask(device) == current_id, "High task bits were ignored for MCI\n");
    check_wow_app_exit_timer(&timer, TIMERR_NOCANDO);
#endif

    timer = create_wow_app_exit_timer(data.event);
    app_exit(current_id);
    if (device)
    {
        ok(!mciGetCreatorTask(device), "Current task's MCI device is still open\n");
        if (mciGetCreatorTask(device)) mciSendCommandA(device, MCI_CLOSE, MCI_WAIT, 0);
        device = 0;
    }
    check_wow_app_exit_timer(&timer, TIMERR_NOCANDO);
    app_exit(current_id);
    check_wow_app_exit_timer(&data.timers[1], TIMERR_NOERROR);

    /* Keep the worker alive: the main thread must be able to clean up its timers. */
    app_exit(thread_id);
    check_wow_app_exit_timer(&data.timers[2], TIMERR_NOCANDO);
    app_exit(thread_id);

    device = open_wow_app_exit_device();
    timer = create_wow_app_exit_timer(data.event);
    /* Task zero may also affect the timer thread, so do not create timers after this. */
    app_exit(0);
    app_exit(0);
    if (device)
        ok((ULONG_PTR)mciGetCreatorTask(device) == current_id, "Task zero closed the MCI device\n");
    check_wow_app_exit_timer(&timer, TIMERR_NOERROR);

done:
    if (thread)
    {
        SetEvent(data.done);
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    for (i = 0; i < ARRAY_SIZE(data.timers); ++i)
        if (data.timers[i]) timeKillEvent(data.timers[i]);
    if (timer) timeKillEvent(timer);
    if (device)
    {
        err = mciSendCommandA(device, MCI_CLOSE, MCI_WAIT, 0);
        ok(!err, "MCI_CLOSE failed, error %lu\n", err);
    }
    if (data.event) CloseHandle(data.event);
    if (data.done) CloseHandle(data.done);
    if (data.ready) CloseHandle(data.ready);
    FreeLibrary(module);
}

START_TEST(winmm)
{
    test_WOW32ResolveMultiMediaHandle();
    test_wow_message_exports();
    test_mmDrvInstall();
    test_WOWAppExit();
}
