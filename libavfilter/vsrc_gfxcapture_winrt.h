/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef AVFILTER_VSRC_GFXCAPTURE_WINRT_H
#define AVFILTER_VSRC_GFXCAPTURE_WINRT_H

#include <functional>
#include <atomic>

#if !HAVE_IDIRECT3DDXGIINTERFACEACCESS
namespace Windows::Graphics::DirectX::Direct3D11 {
    MIDL_INTERFACE("A9B3D012-3DF2-4EE3-B8D1-8695F457D3C1")
    IDirect3DDxgiInterfaceAccess : public IUnknown
    {
        public:
        IFACEMETHOD(GetInterface)(REFIID iid, _COM_Outptr_ void** p) = 0;
    };
}
#ifdef __MINGW32__
__CRT_UUID_DECL(Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess,
                0xa9b3d012, 0x3df2, 0x4ee3, 0xb8, 0xd1, 0x86, 0x95, 0xf4, 0x57, 0xd3, 0xc1)
#endif
#endif /* !HAVE_IDIRECT3DDXGIINTERFACEACCESS */

#if !HAVE___X_ABI_CWINDOWS_CGRAPHICS_CCAPTURE_CIGRAPHICSCAPTURESESSION5
namespace ABI::Windows ::Graphics::Capture {
    MIDL_INTERFACE("67C0EA62-1F85-5061-925A-239BE0AC09CB")
    IGraphicsCaptureSession5 : public IInspectable
    {
        public:
        IFACEMETHOD(get_MinUpdateInterval)(ABI::Windows::Foundation::TimeSpan* value) = 0;
        IFACEMETHOD(put_MinUpdateInterval)(ABI::Windows::Foundation::TimeSpan value) = 0;
    };
}
#ifdef __MINGW32__
__CRT_UUID_DECL(ABI::Windows ::Graphics::Capture::IGraphicsCaptureSession5,
                0x67c0ea62, 0x1f85, 0x5061, 0x92, 0x5a, 0x23, 0x9b, 0xe0, 0xac, 0x09, 0xcb)
#endif
#endif /* !HAVE___X_ABI_CWINDOWS_CGRAPHICS_CCAPTURE_CIGRAPHICSCAPTURESESSION5 */

template<typename... Interfaces>
struct FFComObject : Interfaces...
{
    virtual ~FFComObject() = default;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (!ppvObject)
            return E_POINTER;

        if (query_all<Interfaces...>(riid, ppvObject))
        {
            AddRef();
            return S_OK;
        }

        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return ++ref_count;
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG rc = --ref_count;
        if (rc == 0)
            delete this;
        return rc;
    }

private:
    template <typename Iface, typename... IFaces>
    bool query_all(REFIID riid, void** ppvObject)
    {
        if (riid == __uuidof(Iface)) {
            *ppvObject = static_cast<Iface*>(this);
            return true;
        }
        if constexpr (sizeof...(IFaces)) {
            return query_all<IFaces...>(riid, ppvObject);
        } else if (riid == __uuidof(IUnknown)) {
            *ppvObject = static_cast<IUnknown*>(static_cast<Iface*>(this));
            return true;
        }
        return false;
    }

    std::atomic<ULONG> ref_count { 1 };
};

template<class Iface, typename... Args>
struct FFTypedCBHandler : FFComObject<Iface, IAgileObject>
{
    template <typename F>
    explicit FFTypedCBHandler(F&& f) : cb_func(std::forward<F>(f)) {}

    HRESULT STDMETHODCALLTYPE Invoke(Args... args) override
    {
        if (!cb_func)
            return S_OK;
        return cb_func(args...);
    }

private:
    std::function<HRESULT(Args...)> cb_func;
};

template<class Iface, typename... Args, typename F>
static Microsoft::WRL::ComPtr<Iface> create_cb_handler(F&& cb_func)
{
    return Microsoft::WRL::ComPtr<Iface>(
        new FFTypedCBHandler<Iface, Args...>(std::forward<F>(cb_func))
    );
}

template <typename Ret, typename... Args>
struct Win32Callback {
    std::function<Ret(Args...)> fn;
    static Ret CALLBACK thunk(Args... args, LPARAM lparam) {
        auto self = reinterpret_cast<Win32Callback*>(lparam);
        return self->fn(std::forward<Args>(args)...);
    }
};

template <typename Ret, typename... Args>
auto make_win32_callback(const std::function<Ret(Args...)> &&fn) {
    using T = Win32Callback<Ret, Args...>;
    auto wrapper = std::make_unique<T>(T{ std::forward<decltype(fn)>(fn) });
    auto pair = std::make_pair(&T::thunk, reinterpret_cast<LPARAM>(wrapper.get()));
    return std::make_pair(std::move(wrapper), pair);
}
#define make_win32_callback(...) make_win32_callback(std::function(__VA_ARGS__))

struct HMODULEDeleter {
    typedef HMODULE pointer;
    void operator()(HMODULE handle) const {
        if (handle)
            FreeLibrary(handle);
    }
};
typedef std::unique_ptr<HMODULE, HMODULEDeleter> hmodule_ptr_t;

#define HLSL(shader) #shader

#endif /* AVFILTER_VSRC_GFXCAPTURE_WINRT_H */
