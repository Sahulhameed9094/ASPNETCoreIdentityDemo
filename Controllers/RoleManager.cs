using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCoreIdentityDemo.Controllers
{
    public class RoleManager : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleManager(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
