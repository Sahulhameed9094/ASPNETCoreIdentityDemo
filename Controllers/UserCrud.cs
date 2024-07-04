using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETCoreIdentityDemo.Controllers
{
    public class UserCrud : Controller
    {
        /// <summary>
        /// https://dotnettutorials.net/lesson/usermanager-signinmanager-rolemanager-in-asp-net-core-identity/
        /// </summary>
        private readonly UserManager<IdentityUser> _userManager;

        public UserCrud(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }


        public async Task<IdentityUser> GetById(string id)
        {
            return await _userManager.FindByIdAsync(id);
        }
    }
}
