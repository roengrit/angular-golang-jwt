import { Component, TemplateRef, Input, ElementRef } from '@angular/core';
import { HttpClient ,HttpHeaders } from '@angular/common/http';
import { Http, Headers, RequestOptions, ResponseContentType} from '@angular/http';
import { Injectable } from '@angular/core'; 
import { Router } from '@angular/router';
interface Task {
  title: string,
  is_canceled: boolean
}

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
@Injectable()
export class AppComponent {
  TOKEN_KEY = 'token';
  constructor(
    private http: HttpClient,
    private httpHomw: Http,
  ) { }
  tasks: Array<Task> = [
    {
      title: "Go home",
      is_canceled: false
    },
    {
      title: "Take a nap",
      is_canceled: false
    },
    {
      title: "Start learning Angular with Sabuj",
      is_canceled: false
    }
  ];

  get token() {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  clearToDo() {
    let do_delete = confirm("Are you sure to delete all tasks?");
    if (do_delete) {
      this.tasks.splice(0);
    }
  }

  addTask(input) {
    let value = input.value;
    input.value = "";
    this.tasks.push(
      {
        title: value,
        is_canceled: false
      });
  }

  cancelTask(idx: number) {
    if (this.tasks[idx].is_canceled) {
      this.tasks[idx].is_canceled = false;
    } else {
      this.tasks[idx].is_canceled = true;
    }
  }

  deleteTask(idx: number) {
    let do_delete = confirm("Are you sure to delete the task?");
    if (do_delete) {
      this.tasks.splice(idx, 1);
    }
  }

  editTask(idx: number) {
    let title = this.tasks[idx].title;
    let result = prompt("Edit Task Title", title);
    if (result !== null && result !== "") {
      this.tasks[idx].title = result;
    }
  }

  logIn() {
    var params = {
      email: 'admin@gmail.com',
      password: 'admin123',
    }
    this.http.post('http://localhost:1337/login', JSON.stringify(params)).subscribe((res: any) => {
      localStorage.setItem(this.TOKEN_KEY, res.token);
      console.log(res.token)
    },
      error => {
        alert("Error");
      }
    );
  }

  getAccount() {
    let headers = new HttpHeaders();
    headers = headers.set('Content-Type', 'application/json; charset=utf-8');
    headers = headers.set('Authorization', 'Bearer ' + this.token)
    console.log(this.token)
    this.http.get('http://localhost:1337/account',{headers: headers}).subscribe((res: any) => {
       console.log(res)
    },
      error => {
        alert("Error");
      }
    );
  }
}