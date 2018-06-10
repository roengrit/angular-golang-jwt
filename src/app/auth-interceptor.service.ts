import { Injectable, Injector } from '@angular/core';
import { HttpInterceptor } from '@angular/common/http';
import { AppComponent } from './app.component';

@Injectable()
export class AuthInterceptorService implements HttpInterceptor {
    constructor(private injector: Injector) { }
    intercept(req, next) {
        const authService = this.injector.get(AppComponent);
        const authRequest = req.clone({
            headers: req.headers.set('Authorization', 'Bearer ' + authService.token)
        });
        console.log('Append')
        return next.handle(authRequest);
    }
}
