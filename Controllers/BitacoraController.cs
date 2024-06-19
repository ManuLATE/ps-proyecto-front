using frontendnet.Models;
using frontendnet.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace frontendnet;

[Authorize(Roles = "Administrador")]
public class BitacoraController(BitacoraClientService bitacora) : Controller
{
    public async Task<IActionResult> IndexAsync()
    {
        List<Bitacora>? lista = [];
        try
        {
            lista = await bitacora.GetAsync();
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
        }
        return View(lista);
    }
}