using System.Security.Claims;
using frontendnet.Models;
using frontendnet.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace frontendnet;

public class AuthController(AuthClientService auth) : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View();
    }

    [AllowAnonymous]
    public IActionResult Registrar()
    {
        return View();
    }

    [Authorize(Roles = "NoVerificado")]
    public IActionResult VerificarCorreo()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> IndexAsync(Login model)
    {
        if (ModelState.IsValid)
        {
            try
            {
                // Esta función verifica en backend que el correo y contraseña sean válidos
                var token = await auth.ObtenTokenAsync(model.Email, model.Password);
                var claims = new List<Claim>
                    {
                        // Todo esto se guarda en la Cookie
                        new(ClaimTypes.Name, token.Email),
                        new(ClaimTypes.GivenName, token.Nombre),
                        new("jwt", token.Jwt),
                        new(ClaimTypes.Role, token.Rol),
                    };
                auth.IniciaSesionAsync(claims);
                
                // Si el usuario es válido y tiene un rol diferente a NoVerificado, se redirige a la página principal
                if (token.Rol != "NoVerificado")
                    return RedirectToAction("Index", "Peliculas");
                
                // Sino, se redirige a la página de verificación de correo
                return RedirectToAction("VerificarCorreo", "Auth");
            }
            catch (Exception)
            {
                ModelState.AddModelError("Email", "Credenciales no válidas. Inténtelo nuevamente.");
            }
        }
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegistrarAsync(RegisterUser model)
    {
        if (ModelState.IsValid)
        {
            try
            {
                // Crea un nuevo usuario
                var resultado = await auth.RegistrarUsuarioAsync(model);
                if (resultado)
                {
                    // Usuario creado, iniciar sesión
                    var token = await auth.ObtenTokenAsync(model.Email, model.Password);
                    var claims = new List<Claim>
                    {
                        new(ClaimTypes.Name, token.Email ?? string.Empty),
                        new(ClaimTypes.GivenName, token.Nombre ?? string.Empty),
                        new("jwt", token.Jwt ?? string.Empty),
                        new(ClaimTypes.Role, token.Rol ?? string.Empty),
                    };

                    auth.IniciaSesionAsync(claims);

                    // Usuario válido, ir a la verificación de correo
                    return RedirectToAction("VerificarCorreo", "Auth");
                }
                else
                {
                    ModelState.AddModelError("Email", "No ha sido posible realizar la acción. Inténtelo nuevamente.");
                }
            }
            catch (Exception)
            {
                ModelState.AddModelError("Email", "Credenciales no válidas. Inténtelo nuevamente.");
            }
        }
        return View(model);
    }

    [HttpPost]
    [Authorize(Roles = "NoVerificado")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerificarCorreo(UserOTP model)
    {
        if (ModelState.IsValid)
        {
            try
            {
                // Verifica el código OTP
                var resultado = await auth.VerificarCorreoAsync(model);
                if (resultado)
                {
                    return RedirectToAction("Index", "Auth");
                }
                else
                {
                    ModelState.AddModelError("Code", "No ha sido posible realizar la acción. Inténtelo nuevamente.");
                }
            }
            catch (Exception)
            {
                ModelState.AddModelError("Email", "Credenciales no válidas. Inténtelo nuevamente.");
            }
        }
        return View(model);
    }

    [Authorize(Roles = "Administrador, Usuario, NoVerificado")]
    public async Task<IActionResult> SalirAsync()
    {
        // Cierra la sesión
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        // Sino, se redirige a la página inicial
        return RedirectToAction("Index", "Auth");
    }
}
