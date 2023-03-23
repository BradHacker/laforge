import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';

import { ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { Routes, RouterModule } from '@angular/router';

import { ViewComponentsModule } from '../components/view-components.module';

import { LayoutComponent } from './_layout/layout.component';

const routes: Routes = [
  {
    path: '',
    component: LayoutComponent,
    children: [
      {
        path: 'home',
        loadChildren: () => import('./home/home.module').then((m) => m.HomeModule)
      },
      {
        path: 'dashboard',
        loadChildren: () => import('./dashboard/dashboard.module').then((m) => m.DashboardModule)
      },
      {
        path: 'build/:id',
        loadChildren: () => import('./build/build.module').then((m) => m.BuildModule)
      },
      {
        path: 'manage/:id',
        loadChildren: () => import('./manage/manage.module').then((m) => m.ManageModule)
      },
      // {
      //   path: 'monitor',
      //   loadChildren: () => import('./monitor/monitor.module').then((m) => m.MonitorModule)
      // },
      {
        path: 'plan/:id',
        loadChildren: () => import('./plan/plan.module').then((m) => m.PlanModule)
      },
      {
        path: 'admin',
        loadChildren: () => import('./admin/admin.module').then((m) => m.AdminModule)
      },
      // {
      //   path: 'test',
      //   loadChildren: () => import('./test/test.module').then((m) => m.TestModule)
      // },
      {
        path: 'account',
        loadChildren: () => import('./account/account.module').then((m) => m.AccountModule)
      },
      {
        path: 'splash',
        loadChildren: () => import('../_metronic/partials/layout/splash-screen/splash-screen.module').then((m) => m.SplashScreenModule)
      },
      {
        path: 'user-management',
        loadChildren: () => import('../modules/user-management/user-management.module').then((m) => m.UserManagementModule)
      },
      {
        path: '',
        redirectTo: 'home',
        pathMatch: 'full'
      },
      {
        path: '**',
        redirectTo: 'errors/404',
        pathMatch: 'full'
      }
    ]
  }
];

@NgModule({
  declarations: [],
  imports: [
    CommonModule,
    RouterModule.forChild(routes),
    MatCardModule,
    MatFormFieldModule,
    ReactiveFormsModule,
    MatSelectModule,
    MatInputModule,
    ViewComponentsModule,
    MatTableModule,
    MatButtonModule
  ],
  exports: [RouterModule]
})
export class PagesRoutingModule {}
